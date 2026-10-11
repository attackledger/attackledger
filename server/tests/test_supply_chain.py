"""Container hardening and supply chain (docs/security-review/SUPPLY_CHAIN.md).

The compose files keep every service on no-new-privileges, no Linux capabilities, a read-only
root filesystem, a non-root user and process and memory ceilings; images are pinned by digest;
Python packages are installed from a hash-pinned lock, the web build from its lockfile."""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
FILES = [["docker-compose.yml"], ["docker-compose.yml", "deploy/compose.prod.yml"]]
DOCKERFILES = ["server/Dockerfile", "worker/Dockerfile", "web/Dockerfile", "e2e/Dockerfile"]
# The one service that keeps root, and the one capability it gets back: the caddy binary
# carries it as a file capability (the kernel refuses to run it without it) and binds 80/443.
ROOT_SERVICES = {"caddy": {"NET_BIND_SERVICE"}}


class _Loader(yaml.SafeLoader):
    """Compose's merge tags (!reset, !override) as plain values, marked so a merge replaces."""


class _Reset(list):
    pass


def _tag(loader, node):
    if isinstance(node, yaml.SequenceNode):
        return _Reset(loader.construct_sequence(node))
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


for _t in ("!reset", "!override"):
    _Loader.add_constructor(_t, _tag)


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _services(files) -> dict:
    services: dict = {}
    for f in files:
        doc = yaml.load((ROOT / f).read_text(), Loader=_Loader)
        for name, svc in (doc.get("services") or {}).items():
            services[name] = _deep_merge(services.get(name, {}), svc or {})
    return services


def _dockerfile_user(dockerfile: str) -> str | None:
    users = re.findall(r"^USER\s+(\S+)", (ROOT / dockerfile).read_text(), re.M)
    return users[-1] if users else None


def _user(name: str, svc: dict) -> str | None:
    if svc.get("user"):
        return str(svc["user"])
    build = svc.get("build") or {}
    if isinstance(build, dict) and build.get("dockerfile"):
        return _dockerfile_user(build["dockerfile"])
    return None


@pytest.mark.parametrize("files", FILES)
def test_every_service_is_hardened(files):
    services = _services(files)
    assert {"db", "api", "gateway", "worker", "web", "lab"} <= set(services)
    for name, svc in services.items():
        assert "no-new-privileges:true" in (svc.get("security_opt") or []), name
        assert svc.get("cap_drop") == ["ALL"], name
        assert set(svc.get("cap_add") or []) == ROOT_SERVICES.get(name, set()), name
        assert svc.get("read_only") is True, name
        assert not svc.get("privileged"), name
        assert svc.get("network_mode") != "host" and svc.get("pid") != "host", name
        limits = ((svc.get("deploy") or {}).get("resources") or {}).get("limits") or {}
        assert int(limits.get("pids") or svc.get("pids_limit") or 0) > 0, f"{name}: no process limit"
        assert limits.get("memory"), f"{name}: no memory limit"
        user = _user(name, svc)
        if name in ROOT_SERVICES:
            continue
        assert user, f"{name}: no user"
        assert user.split(":")[0] not in ("0", "root"), f"{name} runs as root"


@pytest.mark.parametrize("files", FILES)
def test_services_that_bind_a_low_port_say_how(files):
    """Non-root services binding a port below 1024 (the gateway's 53, nginx's 80) rely on the
    unprivileged-port sysctl, not on a capability."""
    services = _services(files)
    for name in ("gateway", "web", "lab"):
        assert str((services[name].get("sysctls") or {}).get("net.ipv4.ip_unprivileged_port_start")) == "0", name


@pytest.mark.parametrize("files", FILES)
def test_writable_places_are_tmpfs_and_never_executable(files):
    for name, svc in _services(files).items():
        for entry in svc.get("tmpfs") or []:
            path, _, opts = entry.partition(":")
            flags = set(opts.split(","))
            assert {"noexec", "nosuid", "nodev"} <= flags, (name, path)
            assert any(f.startswith("size=") for f in flags), (name, path)


@pytest.mark.parametrize("files", FILES)
def test_images_are_pinned_by_digest(files):
    for name, svc in _services(files).items():
        image = svc.get("image")
        if image and not svc.get("build"):
            assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"{name}: {image}"


@pytest.mark.parametrize("dockerfile", DOCKERFILES)
def test_dockerfile_base_images_are_pinned_by_digest(dockerfile):
    froms = re.findall(r"^FROM\s+(\S+)", (ROOT / dockerfile).read_text(), re.M)
    assert froms
    for ref in froms:
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), f"{dockerfile}: {ref}"


@pytest.mark.parametrize("dockerfile", ["server/Dockerfile", "worker/Dockerfile"])
def test_every_pip_install_is_hash_pinned(dockerfile):
    lines = [ln for ln in (ROOT / dockerfile).read_text().splitlines() if not ln.lstrip().startswith("#")]
    text = "\n".join(lines).replace("\\\n", " ")
    installs = re.findall(r"pip install[^&\n]*", text)
    assert installs
    for cmd in installs:
        assert "--require-hashes" in cmd and "--no-deps" in cmd and " -r " in cmd, cmd


def _locked(path: Path) -> dict[str, tuple[str, int]]:
    """name -> (version, number of hashes) of a pip-compile lock."""
    out, name = {}, None
    for line in path.read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==(\S+)", line)
        if m:
            name = m.group(1).lower().replace("_", "-")
            out[name] = (m.group(2), 0)
        elif name and "--hash=sha256:" in line:
            v, n = out[name]
            out[name] = (v, n + 1)
    return out


LOCKS = ["server/requirements.txt", "server/requirements-pip.txt", "worker/requirements-arjun.txt",
         "worker/requirements-arjun-build.txt", "tools/ci/requirements-audit.txt"]


@pytest.mark.parametrize("lock", LOCKS)
def test_locks_hash_every_package_and_match_their_input(lock):
    locked = _locked(ROOT / lock)
    assert locked
    for name, (version, hashes) in locked.items():
        assert hashes >= 1, f"{lock}: {name} has no hash"
    src = (ROOT / lock).with_suffix(".in")
    for line in src.read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?==(\S+)", line.strip())
        if m:
            name = m.group(1).lower().replace("_", "-")
            assert locked.get(name, (None,))[0] == m.group(2), f"{lock} is not locked from {src.name}: {name}"
    # Nothing but pins and hashes: no index, no URL, no editable or local path.
    for line in (ROOT / lock).read_text().splitlines():
        s = line.strip()
        assert not s.startswith(("-e", "--index-url", "--extra-index-url", "-i ", "-f", "--find-links")), s
        assert "://" not in s and not s.startswith((".", "/")), s


def test_web_build_installs_the_lockfile_without_scripts():
    text = (ROOT / "web/Dockerfile").read_text()
    assert re.search(r"^RUN npm ci .*--ignore-scripts", text, re.M)
    assert "npm install" not in text
    lock = (ROOT / "web/package-lock.json").read_text()
    resolved = set(re.findall(r'"resolved": "(https://[^/"]+)/', lock))
    assert resolved == {"https://registry.npmjs.org"}
    assert lock.count('"resolved"') == lock.count('"integrity": "sha512-')


def _workflow_uses(node):
    """Every `uses:` in a parsed workflow: steps' actions and jobs' reusable workflows."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "uses":
                yield v
            else:
                yield from _workflow_uses(v)
    elif isinstance(node, list):
        for v in node:
            yield from _workflow_uses(v)


def test_github_actions_are_pinned_by_commit():
    """A tag (actions/checkout@v4) can be moved to other code by whoever controls the action's
    repository; a full commit SHA cannot. Each pin names its tag in a comment, for people and
    for moving the pin (docs/SUPPLY_CHAIN.md)."""
    workflows = sorted((ROOT / ".github/workflows").glob("*.y*ml"))
    assert workflows
    seen = 0
    for wf in workflows:
        text = wf.read_text()
        parsed = list(_workflow_uses(yaml.safe_load(text)))
        lines = re.findall(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$", text, re.M)
        assert sorted(u for u, _ in lines) == sorted(parsed), f"{wf.name}: a uses: the line check does not see"
        for ref, rest in lines:
            seen += 1
            if ref.startswith("./"):
                continue                    # an action of this repository, at the same commit
            assert re.fullmatch(r"[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}", ref), f"{wf.name}: {ref} is not pinned by commit"
            assert re.match(r"\s+#\s*v\d", rest), f"{wf.name}: {ref} has no tag comment"
    assert seen >= 5


@pytest.mark.parametrize("files", FILES)
def test_configs_are_files(files):
    """Compose writes a config's inline `content` into the container, which a read-only root
    filesystem refuses ("`file` is the sole supported option"): measured with Compose 5.6."""
    for f in files:
        for name, conf in (yaml.load((ROOT / f).read_text(), Loader=_Loader).get("configs") or {}).items():
            assert set(conf) == {"file"}, f"{f}: config {name}"
            assert (ROOT / conf["file"]).is_file(), conf["file"]


def _run_lines(dockerfile: str) -> str:
    lines = [ln for ln in (ROOT / dockerfile).read_text().splitlines() if not ln.lstrip().startswith("#")]
    return "\n".join(lines).replace("\\\n", " ")


@pytest.mark.parametrize("dockerfile", DOCKERFILES)
def test_os_packages_are_installed_as_decided(dockerfile):
    """OS packages are not pinned to exact versions (docs/SUPPLY_CHAIN.md, "OS packages"): the
    Debian and Alpine mirrors keep only the newest build of each, so an exact pin breaks the
    build at the next security update. An Alpine package raised for a scan finding names a
    floor (`pkg>=version`); apt installs without recommended packages, apk without a cache."""
    text = _run_lines(dockerfile)
    for cmd in re.findall(r"apt-get install[^&\n]*", text):
        assert "--no-install-recommends" in cmd, cmd
        for arg in cmd.split()[2:]:
            assert "=" not in arg.strip("'\""), f"{dockerfile}: {arg} (exact apt pin)"
    for cmd in re.findall(r"apk (?:add|upgrade)[^&\n]*", text):
        assert "--no-cache" in cmd, cmd
        for arg in (a.strip("'\"") for a in cmd.split()[2:] if not a.startswith("-")):
            assert re.fullmatch(r"[a-z0-9][\w.+-]*(>=[\w.+-]+)?", arg), f"{dockerfile}: {arg} (only a floor, >=)"


def test_image_scanner_is_pinned_by_digest():
    text = (ROOT / "tools/scan_images.sh").read_text()
    refs = re.findall(r"^GRYPE=(\S+)", text, re.M)
    assert len(refs) == 1 and re.fullmatch(r"anchore/grype:v[\d.]+-nonroot@sha256:[0-9a-f]{64}", refs[0]), refs
    assert "--network none" in text          # the scans themselves have no network


def test_scan_ignore_entries_name_a_reason_and_an_end():
    """Each accepted finding of tools/scan_images.sh: an id, an image it runs as published (an
    image built here gets the fix in its Dockerfile instead), the package, an end date and a reason."""
    import datetime
    import fnmatch
    published = {svc["image"] for files in FILES for svc in _services(files).values()
                 if svc.get("image") and not svc.get("build")}
    lines = [ln for ln in (ROOT / "tools/scan_ignore.txt").read_text().splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")]
    for line in lines:
        vid, image, package, until, *reason = line.split()
        assert re.fullmatch(r"(CVE-\d{4}-\d+|GHSA(-[0-9a-z]{4}){3}|GO-\d{4}-\d+)", vid), line
        assert any(fnmatch.fnmatch(p, image) for p in published), f"no published image matches: {line}"
        assert not image.startswith("attackledger-"), line
        # An OS package (zlib), or in a Go binary a Go module (golang.org/x/net) or Go itself (stdlib).
        assert re.fullmatch(r"[a-z0-9][\w.+-]*(/[\w.+~-]+)*", package), line
        datetime.date.fromisoformat(until)
        assert len(reason) >= 3, f"no reason: {line}"


def test_every_lock_is_made_by_the_lock_script_and_tested():
    """Each requirements*.in in the tree is locked by tools/lock_requirements.sh, its lock is in
    LOCKS (hashes, no index), and the weekly pip-audit reads it."""
    tracked = {str(p.relative_to(ROOT)) for p in ROOT.glob("**/requirements*.in")
               if "node_modules" not in p.parts and ".git" not in p.parts}
    script = (ROOT / "tools/lock_requirements.sh").read_text()
    listed = set(re.findall(r'^\s*"([\w./-]+\.in)(?: unsafe)?"$', script, re.M))
    assert tracked and tracked == listed
    assert {f[:-3] + ".txt" for f in tracked} == set(LOCKS)
    audit = next(str(s["run"]) for s in _steps(_workflow("security.yml")) if "pip-audit\" --disable-pip" in str(s.get("run")))
    for lock in LOCKS:
        assert re.search(rf"(^|\s){re.escape(lock)}(\s|;|$)", audit), f"pip-audit does not read {lock}"


# ---- the GitHub workflows ---------------------------------------------------------------------

WORKFLOWS = sorted((ROOT / ".github/workflows").glob("*.y*ml"))
# The one workflow with pull_request_target and write permissions: CLA Assistant Lite stores the
# signatures in this repository. It must never run the pull request's code.
CLA = "cla.yml"


def _workflow(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def _on(wf: dict) -> dict:
    on = wf.get("on", wf.get(True))         # YAML 1.1 reads a bare `on:` key as True
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return dict.fromkeys(on)
    return on or {}


def _steps(wf: dict):
    for job in (wf.get("jobs") or {}).values():
        yield from job.get("steps") or []


def _run_text(wf: dict) -> str:
    return "\n".join(str(s.get("run", "")) for s in _steps(wf))


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_are_read_only_and_use_no_secrets(path):
    """Every workflow but the CLA one runs with a token that can only read the repository, at
    the top and in each job, uses no secret, and is not started by pull_request_target or
    workflow_run (which run with the base repository's token on someone else's changes)."""
    if path.name == CLA:
        return
    wf = yaml.safe_load(path.read_text())
    assert wf.get("permissions") == {"contents": "read"}, path.name
    for name, job in wf["jobs"].items():
        perms = job.get("permissions")
        assert perms is None or (isinstance(perms, dict) and set(perms.values()) <= {"read", "none"}), (path.name, name)
    assert not {"pull_request_target", "workflow_run"} & set(_on(wf)), path.name
    assert "secrets." not in path.read_text(), path.name
    assert "pull_request_target" not in path.read_text(), path.name


def test_only_the_cla_workflow_runs_on_pull_request_target_and_runs_no_code():
    with_target = [p.name for p in WORKFLOWS if "pull_request_target" in _on(yaml.safe_load(p.read_text()))]
    assert with_target == [CLA]
    steps = list(_steps(_workflow(CLA)))
    assert steps and all("run" not in s for s in steps)
    assert all(str(s.get("uses", "")).startswith("contributor-assistant/github-action@") for s in steps)


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_checkouts_keep_no_token_and_installs_run_no_scripts(path):
    """actions/checkout leaves the job's token in .git/config unless told not to; npm ci runs
    install scripts unless told not to (as web/Dockerfile does)."""
    wf = yaml.safe_load(path.read_text())
    for step in _steps(wf):
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert (step.get("with") or {}).get("persist-credentials") is False, path.name
    for cmd in re.findall(r"npm (?:ci|install)[^\n]*", _run_text(wf)):
        assert "--ignore-scripts" in cmd, cmd
    for key in ("container", "services"):
        for job in wf["jobs"].values():
            images = [job.get(key)] if key == "container" else list((job.get(key) or {}).values())
            for image in images:
                ref = image.get("image") if isinstance(image, dict) else image
                assert ref is None or re.search(r"@sha256:[0-9a-f]{64}$", ref), ref


def test_ci_runs_what_contributors_run():
    """The tests workflow runs the SQLite suite (with the default fuzz tests), the Postgres
    suite, the verifier equivalence and its seeded fuzzing, the type check, the web build and
    the workflow lint, on every push and pull request."""
    wf = _workflow("tests.yml")
    assert {"push", "pull_request"} <= set(_on(wf))
    text = _run_text(wf)
    for command in ("python -m pytest -q server/tests", "tools/test_postgres.sh",
                    "tools/verifier_equivalence/run.sh\n", "npx tsc --noEmit", "npm run lint",
                    "npm run build", "tools/lint_workflows.sh"):
        assert command in text + "\n", command
    assert re.search(r"tools/verifier_equivalence/run\.sh --fuzz \d+ --seed \d+", text)
    assert (ROOT / "server/tests/test_fuzz.py").exists() and (ROOT / "server/tests/test_security_fuzz.py").exists()


def test_security_workflow_runs_weekly_and_fails_on_findings():
    wf = _workflow("security.yml")
    on = _on(wf)
    assert set(on) == {"schedule", "workflow_dispatch"}
    assert [c["cron"] for c in on["schedule"]] and all(len(c["cron"].split()) == 5 for c in on["schedule"])
    assert (wf.get("defaults") or {}).get("run", {}).get("shell") == "bash"     # -eo pipefail
    text = _run_text(wf)
    for command in ("tools/scan_images.sh", "tools/refresh_pins.sh", "tools/sbom.sh",
                    'pip-audit" --disable-pip --require-hashes',
                    "npm audit --omit=dev --package-lock-only",
                    "npm audit --package-lock-only --audit-level=high",
                    "--require-hashes --no-deps --only-binary :all: -r tools/ci/requirements-audit.txt"):
        assert command in text, command
    # A scan finding (exit 1) and a failed scan fail the job; a stale pin (exit 1) only warns.
    scan = next(s["run"] for s in _steps(wf) if "tools/scan_images.sh" in str(s.get("run")))
    assert re.search(r"1\) echo \"::error[^\n]*exit 1", scan)
    pins = next(s["run"] for s in _steps(wf) if "tools/refresh_pins.sh" in str(s.get("run")))
    assert re.search(r"1\) echo \"::warning[^\n]*;;", pins) and "exit 1" not in pins
    uploads = [s for s in _steps(wf) if str(s.get("uses", "")).startswith("actions/upload-artifact@")]
    assert uploads and all("!cancelled()" in str(s.get("if")) for s in uploads)


def test_workflow_lint_and_scanner_images_are_pinned_by_digest():
    text = (ROOT / "tools/lint_workflows.sh").read_text()
    refs = re.findall(r"^ACTIONLINT=(\S+)", text, re.M)
    assert len(refs) == 1 and re.fullmatch(r"rhysd/actionlint:[\d.]+@sha256:[0-9a-f]{64}", refs[0]), refs
    assert "--network none" in text


def test_image_scan_reads_go_binaries_and_fails_on_expired_entries():
    """The image scan gives Grype each image's Go binaries as well as its package databases, and
    an entry of scan_ignore.txt past its date fails it, as a finding does."""
    text = (ROOT / "tools/scan_images.sh").read_text()
    assert "docker export" in text and "Go buildinf:" in text
    assert "sys.exit(1 if fixable or expired else 0)" in text


def test_dependabot_covers_every_dependency_with_the_two_week_rule():
    """Weekly, grouped, with a cooldown of at least 14 days (the newest release at least two
    weeks old, docs/SUPPLY_CHAIN.md), for every place a dependency is declared."""
    conf = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    assert conf["version"] == 2
    dirs: dict[str, set] = {}
    for u in conf["updates"]:
        eco = u["package-ecosystem"]
        assert u["schedule"]["interval"] == "weekly", eco
        assert int((u.get("cooldown") or {}).get("default-days", 0)) >= 14, eco
        assert u.get("groups"), eco
        dirs.setdefault(eco, set()).update(u.get("directories") or [u["directory"]])
    assert dirs["github-actions"] == {"/"}
    assert dirs["pip"] == {"/" + str(Path(lock).parent) for lock in LOCKS}
    assert dirs["docker"] == {"/" + str(Path(d).parent) for d in DOCKERFILES}
    assert dirs["docker-compose"] == {"/" + str(Path(f).parent).replace(".", "") for f in FILES[1]}
    npm = {"/" + str(p.parent.relative_to(ROOT)) for p in ROOT.glob("*/package-lock.json")}
    assert npm and dirs["npm"] == npm
