"""Progress lines are short, honest about the agent's claims, and never the raw stream."""

import json

from actenon_airlock.progress import Progress


def feed(progress, value):
    raw = value if isinstance(value, str) else json.dumps(value)
    return progress.feed((raw + "\n").encode())


def test_events_become_short_lines():
    p = Progress()
    assert feed(p, {"type": "system", "subtype": "init", "model": "m"}) == [
        "  started   m in the sealed container"
    ]
    bash = {"type": "tool_use", "name": "Bash", "input": {"command": "go test ./...\nmore"}}
    assert feed(p, {"type": "assistant", "message": {"content": [bash]}}) == [
        "  running   go test ./..."
    ]
    result = {"type": "tool_result", "content": [{"type": "text", "text": "ok  example 0.01s"}]}
    assert feed(p, {"type": "user", "message": {"content": [result]}}) == [
        "            → ok example 0.01s"
    ]
    failed = {"type": "tool_result", "is_error": True, "content": "boom"}
    assert feed(p, {"type": "user", "message": {"content": [failed]}}) == [
        "            → the command failed"
    ]


def test_the_agents_last_words_are_labelled_as_its_claim():
    lines = feed(Progress(), {"type": "result", "num_turns": 2, "result": "All done, tests pass."})
    assert lines[1] == "  The agent says: All done, tests pass."
    assert "its own words" in lines[2]


def test_supervisor_lines_are_counted_or_shown_and_noise_is_only_logged():
    p = Progress()
    assert feed(p, "AIRLOCK ALLOW http.post @ https://x/v1/messages: effect COMMITTED [r]") == []
    assert p.model_calls == 1
    deny = "AIRLOCK DENY http.post @ https://evil: No reviewed protected consequence profile [r2]"
    assert feed(p, deny) == ["  refused   No reviewed protected consequence profile"]
    assert feed(p, "AIRLOCK PROTECTED MODE: compute inside") == []
    assert feed(p, "some unrelated output") == []
    assert feed(p, '{"type": "stream_event", "huge": "' + "x" * 5000 + '"}') == []
    assert feed(p, "{not json") == []
