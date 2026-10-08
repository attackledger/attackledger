"""AttackLedger worker: claims queued jobs and runs recon tools.

Defense in depth: the API validates targets when a job is created, and the
worker re-checks every target before running and every host a tool reports
before storing it. Nothing outside the engagement's scope rules is recorded.
"""
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, "/srv")  # server package (app.*) is copied next to the worker

from sqlalchemy import select, text  # noqa: E402

from app import ledger, packs, scope  # noqa: E402
from app.db import Base, SessionLocal, engine  # noqa: E402
from app.models import Asset, Engagement, Job, JobStatus, Observation  # noqa: E402

POLL_SECONDS = float(os.environ.get("WORKER_POLL_SECONDS", "2"))
JOB_TIMEOUT = int(os.environ.get("WORKER_JOB_TIMEOUT", "1800"))
TOOLS = os.environ.get("WORKER_TOOLS_DIR", "/opt/pd/bin")


def tool(name: str) -> str:
    return os.path.join(TOOLS, name)


def now():
    return datetime.now(timezone.utc)


def identification_flags(eng) -> list[str]:
    flags = []
    if eng.research_header:
        flags += ["-H", eng.research_header]
    if eng.research_user_agent:
        flags += ["-H", f"User-Agent: {eng.research_user_agent}"]
    return flags


def command(kind: str, eng) -> list[str]:
    rps = eng.rate_limit_rps
    if kind == "subdomains":
        # Passive sources only: subfinder queries third-party datasets, not the target.
        return [tool("subfinder"), "-silent", "-oJ", "-dL", "-"]
    if kind == "resolve":
        return [tool("dnsx"), "-silent", "-json", "-a", "-aaaa", "-cname", "-rl", str(rps)]
    if kind == "probe":
        # No redirect following: a redirect could lead outside scope.
        flags = identification_flags(eng)
        if not flags:  # fail closed, independent of the API check
            raise RuntimeError("no research header or user agent set; refusing to send traffic")
        return [tool("httpx"), "-silent", "-json", "-status-code", "-title", "-tech-detect",
                "-web-server", "-ip", "-location", "-rl", str(rps), "-t", "10", *flags]
    raise ValueError(f"unknown job kind {kind}")


def parse(kind: str, rec: dict) -> tuple[str | None, dict]:
    if kind == "subdomains":
        return rec.get("host"), {"source": rec.get("source")}
    if kind == "resolve":
        return rec.get("host"), {"a": rec.get("a", []), "aaaa": rec.get("aaaa", []),
                                 "cname": rec.get("cname", [])}
    if kind == "probe":
        host = rec.get("input") or rec.get("host")
        return host, {"url": rec.get("url"), "status_code": rec.get("status_code"),
                      "title": rec.get("title"), "tech": rec.get("tech", []),
                      "webserver": rec.get("webserver"), "location": rec.get("location"),
                      "live": True}
    return None, {}


def claim(session):
    stmt = select(Job).where(Job.status == JobStatus.queued).order_by(Job.id).limit(1)
    if engine.dialect.name == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)
    job = session.scalars(stmt).first()
    if job:
        job.status, job.started_at = JobStatus.running, now()
        session.commit()
    return job


def append_log(session, job, line):
    job.log = (job.log + line + "\n")[-20000:]
    session.commit()


def cancelled(session, job) -> bool:
    session.refresh(job, ["status"])
    return job.status == JobStatus.cancelled


def run(session, job: Job):
    eng: Engagement = job.engagement
    inc, exc = eng.scope_include, eng.scope_exclude
    roots = {p[2:] for p in inc if p.startswith("*.")}

    if eng.authorized_at is None or not inc:
        raise RuntimeError("engagement is not authorized or has no scope")
    if job.kind == "subdomains":
        targets = [t for t in job.targets if t in roots]
    else:
        targets = [t for t in job.targets if scope.in_scope(t, inc, exc)]
    dropped = set(job.targets) - set(targets)
    if dropped:
        append_log(session, job, f"skipped {len(dropped)} target(s) outside scope")
    if not targets:
        raise RuntimeError("no in-scope targets")

    cmd = command(job.kind, eng)
    append_log(session, job, f"$ {' '.join(cmd)}  ({len(targets)} target(s))")
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    proc.stdin.write("\n".join(targets) + "\n")
    proc.stdin.close()

    digest = hashlib.sha256()
    kept = skipped = 0
    started = time.monotonic()
    known = {a.host: a for a in eng.assets}

    for n, line in enumerate(proc.stdout, start=1):
        digest.update(line.encode())
        try:
            host, data = parse(job.kind, json.loads(line))
        except json.JSONDecodeError:
            continue
        if not host or not scope.in_scope(host, inc, exc):
            skipped += 1
            continue
        host = scope.normalize_host(host)
        session.add(Observation(job_id=job.id, engagement_id=eng.id, host=host, data=data))
        if host not in known:
            known[host] = Asset(engagement_id=eng.id, host=host, in_scope=True)
            session.add(known[host])
        kept += 1
        if n % 25 == 0:
            session.commit()
            if cancelled(session, job) or time.monotonic() - started > JOB_TIMEOUT:
                proc.kill()
                append_log(session, job, "stopped: cancelled or timed out")
                break
    proc.wait()
    err = proc.stderr.read().strip()
    if err:
        append_log(session, job, err[-4000:])

    job.result_count, job.output_sha256 = kept, digest.hexdigest()
    session.commit()
    append_log(session, job, f"kept {kept} in-scope result(s), ignored {skipped} out of scope")

    # Record the run as evidence on each touched host's recon lane, if one is open.
    # It is attached to the lane, not to a checklist item: a person or agent still
    # decides which item it proves.
    recon_lane = packs.get_pack(eng.pack_id).recon_lane
    touched = {o.host for o in session.scalars(select(Observation).where(Observation.job_id == job.id))}
    for host in touched:
        lane = next((l for l in known[host].lanes if l.role == recon_lane), None) if known[host].id else None
        if lane:
            ledger.append_evidence(session, lane, kind="file", sha256_hex=job.output_sha256,
                                   uri=f"job:{job.id}", summary=f"{job.kind} run, job {job.id}")
    session.commit()
    if proc.returncode not in (0, None) and not cancelled(session, job):
        raise RuntimeError(f"tool exited with code {proc.returncode}")


def main():
    Base.metadata.create_all(engine)
    print("worker ready", flush=True)
    while True:
        with SessionLocal() as session:
            job = claim(session)
            if not job:
                time.sleep(POLL_SECONDS)
                continue
            print(f"job {job.id} {job.kind}", flush=True)
            try:
                run(session, job)
                if job.status != JobStatus.cancelled:
                    job.status = JobStatus.done
            except Exception as e:  # report, never crash the loop
                session.rollback()
                job = session.get(Job, job.id)
                append_log(session, job, f"error: {e}")
                job.status = JobStatus.failed
            job.finished_at = now()
            session.commit()


if __name__ == "__main__":
    main()
