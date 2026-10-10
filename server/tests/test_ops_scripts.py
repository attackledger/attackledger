"""tools/backup.sh and tools/restore.sh: two failures found by running them on a fresh Ubuntu server."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_docker_calls_never_read_the_scripts_stdin():
    """From a pipe or a heredoc, `docker compose exec` swallowed the rest of the script."""
    for name in ("backup.sh", "restore.sh"):
        text = (ROOT / "tools" / name).read_text()
        assert 'dc() { docker compose "$@" </dev/null; }' in text, name
        assert not re.search(r"^\s*docker compose ", text, re.M), f"{name}: call docker through dc"


def test_restore_feeds_only_the_dump_and_the_blob_archive():
    text = (ROOT / "tools" / "restore.sh").read_text()
    fed = [line for line in text.splitlines() if line.startswith("dc_in ")]
    assert len(fed) == 2 and "pg_restore" in fed[0] and "run --rm" in fed[1]


def test_restore_does_not_count_the_default_organization_as_data():
    """Migration 0022 makes one organization in every new install, so a wiped install is not empty
    by row count; restore refused it without --force."""
    text = (ROOT / "tools" / "restore.sh").read_text()
    assert "not in ('alembic_version', 'organizations')" in text
