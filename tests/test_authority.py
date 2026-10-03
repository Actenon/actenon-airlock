import json

import pytest

from actenon_airlock.cli import main
from actenon_airlock.manifest import (
    AirlockError,
    authority_diff,
    capability,
    discover,
    request_capability,
    validate_url,
)


def test_scan_evidence_drives_target_diff(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text('import requests\nrequests.post("https://example.com/a")\n')
    a = discover(tmp_path, env={})
    path.write_text('import requests\nrequests.post("https://example.com/b")\n')
    b = discover(tmp_path, env={})
    diff = authority_diff(a, b)
    assert [p["resource"] for p in diff["removed"]] == ["example.com/a"]
    assert [p["resource"] for p in diff["added"]] == ["example.com/b"]
    assert capability(a["powers"][0]) != capability(b["powers"][0])
    assert b["entries"][0]["evidence"]["file"] == "agent.py"


def test_unresolved_call_cannot_inherit_static_authority(tmp_path):
    (tmp_path / "main.py").write_text(
        'import requests\nrequests.post("https://example.com/a")\n'
        "def tool(url):\n    requests.post(url)\nhandlers=[tool]\n"
    )
    manifest = discover(tmp_path, env={})
    assert len(manifest["powers"]) == 1 and len(manifest["blocked"]) == 1
    cap, _ = request_capability(
        manifest, "post", "https://example.com/a", [{"file": "main.py", "line": 4, "col": 2}]
    )
    assert cap.startswith("airlock.unresolved.")


def test_templates_and_empty_authority_fail_closed(tmp_path):
    (tmp_path / "main.py").write_text(
        'import requests\ndef f(id):\n requests.delete(f"https://example.com/items/{id}")\nhandlers=[f]\n'
    )
    m = discover(tmp_path, env={})
    assert m["powers"] == []
    assert m["blocked"][0]["state"] == "TEMPLATE"


def test_github_action_uses_scan_vocabulary(tmp_path):
    (tmp_path / "main.py").write_text(
        'from github import Github\ngh=Github()\ngh.get_repo("acme/support").create_issue(title="x")\n'
    )
    m = discover(tmp_path, env={})
    p = [p for p in m["powers"] if p["action"] == "github.issue.create"][0]
    cap, entry = request_capability(
        m,
        "POST",
        "https://api.github.com/repos/acme/support/issues",
        [{"file": "main.py", "line": 3, "col": 1}],
    )
    assert cap == capability(p) and entry["resource"] == "github.com/acme/support"


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/x",
        "https://u:p@example.com/a",
        "https://example.com/a#fragment",
        "https://example.com/a/../b",
        "https://example.com/a%2fb",
        "https://example.com/a%252fb",
        "https://example.com//a",
        "https://example.com/?api_key=secret",
        "https://example.com/a\\b",
    ],
)
def test_ambiguous_urls_refuse(url):
    with pytest.raises(AirlockError):
        validate_url(url)


def test_scheme_and_query_are_distinct_authority(tmp_path):
    (tmp_path / "main.py").write_text(
        'import requests\nrequests.post("https://example.com/a?x=1")\n'
    )
    m = discover(tmp_path, env={})
    for url in ["http://example.com/a?x=1", "https://example.com/a?x=2"]:
        cap, _ = request_capability(m, "POST", url, [{"file": "main.py", "line": 2, "col": 1}])
        assert cap not in {capability(p) for p in m["powers"]}


def test_tampered_approval_refuses(project):
    state = project('import requests\nrequests.post("https://example.com/a")\n')
    path = state.path / "approved.json"
    envelope = json.loads(path.read_text())
    envelope["payload"]["powers"][0]["resource"] = "attacker.example/a"
    path.write_text(json.dumps(envelope))
    with pytest.raises(AirlockError, match="signature"):
        state.approved()


def test_changed_public_key_refuses(project):
    state = project("print('hello')\n")
    (state.path / "public-key.json").write_text('{"key":"forged"}')
    with pytest.raises(AirlockError, match="trust anchor"):
        state.approved()


def test_parse_error_blocks_approval(tmp_path):
    (tmp_path / "main.py").write_text("def invalid(\n")
    assert main(["init", "--path", str(tmp_path), "--approve"]) == 2
    assert not (tmp_path / ".airlock/approved.json").exists()


def test_init_without_approval_is_proposal_only(tmp_path):
    (tmp_path / "main.py").write_text("print('hello')\n")
    assert main(["init", "--path", str(tmp_path)]) == 0
    assert not (tmp_path / ".airlock/approved.json").exists()
    assert main(["run", "--path", str(tmp_path)]) == 2


def test_check_json_reports_expansion(project, capsys):
    state = project('import requests\nrequests.post("https://example.com/a")\n')
    (state.root / "main.py").write_text(
        'import requests\nrequests.delete("https://example.com/a")\n'
    )
    assert main(["check", "--path", str(state.root), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["added"][0]["action"] == "http.delete"
    assert result["removed"][0]["action"] == "http.post"


def test_reduction_needs_no_new_approval(project):
    state = project('import requests\nrequests.post("https://example.com/a")\n')
    (state.root / "main.py").write_text("print('hello')\n")
    assert main(["check", "--path", str(state.root)]) == 0


def test_unsupported_filesystem_remains_blocked(tmp_path):
    (tmp_path / "main.py").write_text('open("out.txt", "w").write("oops")\n')
    m = discover(tmp_path, env={})
    assert m["powers"] == []
    assert m["blocked"][0]["action"] == "filesystem.write"
