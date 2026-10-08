import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from app import scopeimport

CSV = """identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,max_severity
*.example.com,WILDCARD,,true,true,critical
https://app.example.net/login,URL,,true,true,high
community.example.com,URL,,false,false,none
api.example.com,API,,true,true,high
com.example.app,GOOGLE_PLAY_APP_ID,,true,true,high
10.0.0.0/8,CIDR,,false,true,none
example.org,WILDCARD,,true,true,high
bad host!,URL,,true,true,low
"""


def test_import_turns_ineligible_assets_into_excludes():
    r = scopeimport.parse(CSV)
    assert r["include"] == ["*.example.com", "*.example.org", "api.example.com", "app.example.net"]
    assert r["exclude"] == ["community.example.com"]
    assert {x["type"] for x in r["not_imported"]} == {"GOOGLE_PLAY_APP_ID", "CIDR"}
    assert r["invalid"][0]["identifier"] == "bad host!"


def test_import_needs_an_identifier_column():
    with pytest.raises(ValueError, match="identifier"):
        scopeimport.parse("foo,bar\n1,2\n")
