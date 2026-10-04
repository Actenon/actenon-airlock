import base64
import os
from pathlib import Path

import httpx
import pytest

from actenon_airlock.adapters import (
    CHANNELS,
    REGISTRY,
    Context,
    adapter_for,
    http_candidates,
    scope,
)
from actenon_airlock.broker import Broker
from actenon_airlock.manifest import AirlockError, discover

PATH = os.environ.get("PATH", os.defpath)


def context(root):
    return Context(root=Path(root), home=Path.home(), search_path=PATH)


def proc(argv, executable=None, cwd="/", search_path=PATH, operation="subprocess.Popen"):
    return {
        "operation": operation,
        "executable": executable or argv[0],
        "argv": argv,
        "cwd": cwd,
        "search_path": search_path,
    }


def names(effect):
    return [c["resource"] for c in effect.candidates]


def test_registry_covers_every_power_kind_scan_emits():
    assert set(REGISTRY) == {"http", "github", "process", "filesystem", "email"}
    assert set(CHANNELS) == {"http", "process", "filesystem", "email"}
    assert adapter_for("database.write") is None
    assert REGISTRY["email"].executor is None


def test_plain_and_shell_process_requests_name_scan_programs(tmp_path):
    adapter = REGISTRY["process"]
    assert names(adapter.classify(proc(["touch", "x"]), context(tmp_path))) == ["touch"]
    shell = proc(["/bin/sh", "-c", "touch 'a b'"])
    assert names(adapter.classify(shell, context(tmp_path))) == ["touch", "sh"]
    for text in ["touch a; rm b", "touch $HOME", "touch a | cat", "X=1 touch a", "touch *"]:
        effect = adapter.classify(proc(["/bin/sh", "-c", text]), context(tmp_path))
        assert names(effect) == ["<shell-syntax>"], text
        assert effect.detail["program"] == "sh"
    for argv in (
        ["/bin/bash", "-c", "echo a; echo b"],
        ["/bin/bash", "-s"],
        ["/bin/bash", "payload.sh"],
        ["/bin/sh", "-c", ". ./payload.sh"],
        ["/bin/bash", "-c", "source ./payload.sh"],
        ["/bin/bash", "-c", "exec /bin/bash ./payload.sh"],
        ["/bin/sh", "-c", "/bin/bash ./payload.sh"],
        ["/bin/sh", "-lc", "true"],
        ["/bin/bash", "--rcfile", "payload.sh", "-ic", "true"],
    ):
        effect = adapter.classify(proc(argv), context(tmp_path))
        assert names(effect) == ["<shell-syntax>"], argv
    startup = proc(["/bin/bash", "-c", "true"])
    startup["startup_env"] = ["BASH_ENV"]
    assert names(adapter.classify(startup, context(tmp_path))) == ["<shell-syntax>"]
    for argv in (
        ["/bin/sh", "-c", "python3 -c import os"],
        ["/bin/sh", "-c", "perl -e print"],
        ["/bin/sh", "-c", "env /bin/bash -c true"],
        ["/bin/sh", "-c", "ssh -o ProxyCommand=touch /tmp/x host"],
    ):
        effect = adapter.classify(proc(argv), context(tmp_path))
        assert names(effect) == ["<shell-syntax>"], argv


def test_interpreters_and_wrappers_require_one_plain_program(tmp_path):
    adapter = REGISTRY["process"]
    ctx = context(tmp_path)
    denied = [
        ["python3", "-c", "open('marker.txt','w').write('pwned')"],
        ["perl", "-e", "print 'pwned'"],
        ["node", "-e", "require('fs').writeFileSync('marker.txt','pwned')"],
        ["awk", 'BEGIN{print "pwned" > "marker.txt"}'],
        ["env", "bash", "-c", "echo pwned > marker.txt"],
        ["nice", "bash", "-c", "echo pwned > marker.txt"],
        ["timeout", "5", "bash", "-c", "echo pwned > marker.txt"],
        ["xargs", "-0", "/bin/sh", "-c", "echo pwned > marker.txt"],
        ["stdbuf", "-o0", "bash", "-c", "echo pwned > marker.txt"],
        ["setsid", "bash", "-c", "echo pwned > marker.txt"],
        ["flock", "lock", "/bin/bash", "-c", "echo pwned > marker.txt"],
        ["nohup", "bash", "-c", "echo pwned > marker.txt"],
        ["find", "tree", "-exec", "/bin/sh", "-c", "echo pwned > marker.txt", ";"],
        ["git", "-c", "alias.p=!echo pwned > marker.txt", "p"],
        ["ssh", "-o", "ProxyCommand=echo pwned > marker.txt", "-o", "BatchMode=yes", "127.0.0.1"],
        ["env", "-S", "bash -c true"],
        ["flock", "-c", "echo pwned", "lock"],
        ["watch", "touch", "marker.txt"],
        ["ionice", "bash", "-c", "true"],
        ["unshare", "-r"],
    ]
    for argv in denied:
        effect = adapter.classify(proc(argv), ctx)
        assert names(effect) == ["<shell-syntax>"], argv
    allowed = {
        ("touch", "made.txt"): ["touch"],
        ("env", "touch", "made.txt"): ["touch", "env"],
        ("nice", "-n", "5", "touch", "made.txt"): ["touch", "nice"],
        ("timeout", "5", "touch", "made.txt"): ["touch", "timeout"],
        ("xargs", "touch"): ["touch", "xargs"],
        ("stdbuf", "-o0", "touch", "made.txt"): ["touch", "stdbuf"],
        ("setsid", "touch", "made.txt"): ["touch", "setsid"],
        ("flock", "lock", "touch", "made.txt"): ["touch", "flock"],
        ("nohup", "touch", "made.txt"): ["touch", "nohup"],
        ("find", "tree", "-name", "x"): ["find"],
        ("find", "tree", "-exec", "touch", "{}", ";"): ["touch", "find"],
        ("git", "status"): ["git"],
        ("git", "commit", "-m", "fix!"): ["git"],
        ("ssh", "-o", "BatchMode=yes", "127.0.0.1"): ["ssh"],
        ("ionice", "-c", "3", "touch", "made.txt"): ["touch", "ionice"],
        ("watch", "-x", "touch", "made.txt"): ["touch", "watch"],
        ("taskset", "ff", "touch", "made.txt"): ["touch", "taskset"],
        ("chrt", "--other", "0", "touch", "made.txt"): ["touch", "chrt"],
        ("prlimit", "touch", "made.txt"): ["touch", "prlimit"],
        ("unshare", "-r", "touch", "made.txt"): ["touch", "unshare"],
    }
    for argv, expected in allowed.items():
        assert names(adapter.classify(proc(list(argv)), ctx)) == expected, argv


def test_process_identity_must_match_the_broker_path(tmp_path):
    adapter = REGISTRY["process"]
    fake = tmp_path / "touch"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    with pytest.raises(AirlockError, match="broker PATH"):
        adapter.classify(proc([str(fake), "x"]), context(tmp_path))
    with pytest.raises(AirlockError, match="broker PATH"):
        adapter.classify(proc(["touch", "x"], search_path=str(tmp_path)), context(tmp_path))
    with pytest.raises(AirlockError, match="argv"):
        adapter.classify(proc(["touch", "x"], executable="/bin/rm"), context(tmp_path))
    with pytest.raises(AirlockError, match="not on the broker PATH"):
        adapter.classify(proc(["airlock-no-such-program"]), context(tmp_path))
    with pytest.raises(AirlockError, match="positional"):
        adapter.classify(proc(["/bin/sh", "-c", "true", "x"]), context(tmp_path))


def test_filesystem_requests_use_scan_path_spellings(tmp_path):
    adapter = REGISTRY["filesystem"]
    message = {"operation": "open", "path": "out/x.txt", "cwd": str(tmp_path)}
    effect = adapter.classify(message, context(tmp_path))
    assert names(effect)[0] == "./out/x.txt"
    assert str(tmp_path / "out" / "x.txt") in names(effect)
    assert {c["action"] for c in effect.candidates} == {"filesystem.write"}
    delete = adapter.classify(dict(message, operation="os.remove"), context(tmp_path))
    assert {c["action"] for c in delete.candidates} == {"filesystem.delete"}


@pytest.mark.parametrize(
    "message,reason",
    [
        ({"operation": "open", "path": ".airlock/approved.json"}, "Airlock state"),
        ({"operation": "os.rename", "path": "x", "src": ".airlock/local/key.json"}, "Airlock"),
        ({"operation": "os.remove", "path": "x", "dir_fd": True}, "Directory-descriptor"),
        ({"operation": "os.mknod", "path": "x"}, "Unsupported filesystem operation"),
    ],
)
def test_filesystem_requests_fail_closed(tmp_path, message, reason):
    with pytest.raises(AirlockError, match=reason):
        REGISTRY["filesystem"].classify(dict(message, cwd=str(tmp_path)), context(tmp_path))


def test_http_candidates_include_method_agnostic_scan_spelling():
    candidates = http_candidates("POST", "https://example.com/a")
    assert [c["action"] for c in candidates] == ["http.post", "http.request"]
    graphql = http_candidates("POST", "https://api.github.com/graphql")[0]
    assert graphql == {
        "action": "github.graphql",
        "resource": "github.com",
        "transport": "https://api.github.com",
    }


def test_scope_text_is_buyer_readable():
    text = scope({"action": "process.exec", "resource": "git", "transport": "local-process"})
    assert "plain program" in text
    assert "does not parse a script" in text
    assert "GraphQL" in scope(
        {
            "action": "github.graphql",
            "resource": "github.com",
            "transport": "https://api.github.com",
        }
    )
    assert scope({"action": "database.write", "resource": "x", "transport": "y"}) == (
        "No Airlock adapter"
    )


def http_message(url, line=2, method="POST"):
    return {
        "kind": "http",
        "method": method,
        "url": url,
        "headers": {},
        "body": base64.b64encode(b"{}").decode(),
        "locations": [{"file": "main.py", "line": line, "col": 1}],
    }


def test_github_graphql_is_an_approvable_scan_power(project):
    url = "https://api.github.com/graphql"
    state = project(f'import requests\nrequests.post("{url}", json={{"query": "{{x}}"}})\n')
    current = discover(state.root)
    assert {"action": "github.graphql", "resource": "github.com"}.items() <= current["powers"][
        0
    ].items()
    broker = Broker(state, current)
    sent = []
    broker.http.close()
    broker.http = httpx.Client(
        transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200, json={})),
        trust_env=False,
    )
    try:
        assert broker.handle(http_message(url))["ok"]
        assert not broker.handle(http_message(url, line=9))["ok"]
        assert len(sent) == 1
    finally:
        broker.close()


def test_dynamic_method_binds_scan_http_request_power(project, server):
    url, calls = server
    state = project(f'import requests, sys\nrequests.request(sys.argv[1], "{url}/a")\n')
    current = discover(state.root)
    assert current["powers"][0]["action"] == "http.request"
    broker = Broker(state, current)
    try:
        assert broker.handle(http_message(url + "/a", method="DELETE"))["ok"]
        assert not broker.handle(http_message(url + "/b", method="DELETE"))["ok"]
        assert [c[0] for c in calls] == ["/a"]
    finally:
        broker.close()
