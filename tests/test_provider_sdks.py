import httpx
import pytest

from actenon_airlock.broker import Broker, launch


@pytest.mark.parametrize(
    "source,env_name,body",
    [
        (
            "from openai import OpenAI\n"
            'r=OpenAI().chat.completions.create(model="test", messages=[{"role":"user","content":"hello"}])\n'
            'assert r.choices[0].message.content == "offline"\n',
            "OPENAI_API_KEY",
            {
                "id": "chatcmpl-offline",
                "object": "chat.completion",
                "created": 0,
                "model": "test",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "offline"},
                        "finish_reason": "stop",
                    }
                ],
            },
        ),
        (
            "from anthropic import Anthropic\n"
            'r=Anthropic().messages.create(model="test", max_tokens=10, messages=[{"role":"user","content":"hello"}])\n'
            'assert r.content[0].text == "offline"\n',
            "ANTHROPIC_API_KEY",
            {
                "id": "msg_offline",
                "type": "message",
                "role": "assistant",
                "model": "test",
                "content": [{"type": "text", "text": "offline"}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        ),
        (
            "import os\nfrom github import Github, Auth\n"
            'g=Github(auth=Auth.Token(os.environ["GITHUB_TOKEN"]))\n'
            'issue=g.get_repo("acme/support", lazy=True).create_issue(title="offline")\n'
            "assert issue.number == 1\n",
            "GITHUB_TOKEN",
            {
                "id": 1,
                "number": 1,
                "title": "offline",
                "url": "https://api.github.com/repos/acme/support/issues/1",
            },
        ),
    ],
)
def test_real_sdk_through_real_permit_kernel_without_live_provider(
    project, monkeypatch, source, env_name, body
):
    monkeypatch.setenv(env_name, "offline-secret")
    state = project(source)
    observed = []
    original = Broker.__init__

    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.http.close()

        def transport(req):
            observed.append(req)
            return httpx.Response(200, json=body)

        self.http = httpx.Client(transport=httpx.MockTransport(transport), trust_env=False)

    monkeypatch.setattr(Broker, "__init__", initialize)
    assert launch(state.root, ["main.py"]) == 0
    assert len(observed) == 1
    assert any("offline-secret" in value for value in observed[0].headers.values())
    assert "offline-secret" not in (state.local / "receipts.jsonl").read_text()
