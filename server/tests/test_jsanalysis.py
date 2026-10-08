import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import jsanalysis as js

JS_URL = "https://app.example.com/static/main.js"


def test_endpoints_are_resolved_on_the_files_host():
    text = '''fetch("/api/v1/items?page=1"); x="https://app.example.com/graphql";
              y="https://cdn.other.test/lib.js"; z='v2/orders/list.json'; w="//cdn.example.com/a"'''
    assert js.extract_endpoints(text, JS_URL) == [
        "https://app.example.com/api/v1/items?page=1",
        "https://app.example.com/graphql",
        "https://app.example.com/static/v2/orders/list.json",
    ]


def test_graphql_operations_including_tagged_templates():
    text = 'const Q = gql`query GetUser($id: ID!) { user(id: $id) { id } }`; mutation UpdateCart { x }'
    assert js.graphql_operations(text) == ["mutation UpdateCart", "query GetUser"]


def test_sourcemap_reference():
    assert js.sourcemap_ref("x\n//# sourceMappingURL=main.js.map", JS_URL) == "https://app.example.com/static/main.js.map"
    assert js.sourcemap_ref("//# sourceMappingURL=data:application/json;base64,e30=", JS_URL) == "inline"
    assert js.sourcemap_ref("no map", JS_URL) is None


def test_secret_buckets_real_first_and_values_never_stored():
    aws = "AKIA" + "Q" * 16
    slack = "xoxb-1234567890-ABCdefGHIjklMNOpqrs"   # contains a filler-like run; must stay REAL
    text = f'k="{aws}"; s="{slack}"; p="pk_live_51Habcdefghijk"; t="AKIA{"0" * 16}" // example'
    found = {f["kind"]: f for f in js.scan_secrets(text)}
    assert found["AWS access key id"]["bucket"] in ("real", "noise")
    assert found["Slack token"]["bucket"] == "real" and found["Slack token"]["severity"] == "high"
    assert found["Stripe publishable key"]["bucket"] == "public"
    for f in found.values():
        assert aws not in f["preview"] and slack not in f["preview"] and len(f["value_sha256"]) == 64


def test_template_value_is_noise():
    found = js.scan_secrets('const key = "AKIA' + "X" * 16 + '"; // your_key placeholder')
    assert found[0]["bucket"] == "noise" and found[0]["severity"] == ""


def test_mask():
    assert js.mask("AKIAABCDEFGHIJKLMNOP") == "AKIA…MNOP"
    assert js.mask("short") == "sh…"
