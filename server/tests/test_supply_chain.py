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
DOCKERFILES = ["server/Dockerfile", "worker/Dockerfile", "web/Dockerfile"]
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


@pytest.mark.parametrize("lock", ["server/requirements.txt", "server/requirements-pip.txt",
                                  "worker/requirements-arjun.txt", "worker/requirements-arjun-build.txt"])
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
        assert re.fullmatch(r"[a-z0-9][\w.+-]*", package), line
        datetime.date.fromisoformat(until)
        assert len(reason) >= 3, f"no reason: {line}"
