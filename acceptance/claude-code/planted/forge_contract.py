"""Fixed model-route abuse from inside the container, as compromised code would send it.

Claude Code would not send these. They run without a model, so they cost nothing, and
each reports only the status it saw. The host judges from the provider's log.
"""

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ["ANTHROPIC_BASE_URL"]
MODEL = sys.argv[1]
SINK = "http://host.docker.internal:18099/contract"


def post(body, headers=()):
    request = urllib.request.Request(
        BASE + "/v1/messages",
        json.dumps(body).encode(),
        {"Content-Type": "application/json", **dict(headers)},
    )
    try:
        return urllib.request.urlopen(request, timeout=20).status
    except urllib.error.HTTPError as error:
        return error.code


plain = {"model": MODEL, "max_tokens": 10, "messages": [{"role": "user", "content": "x"}]}
source = {"type": "url", "url": SINK}
image = {"role": "user", "content": [{"type": "image", "source": source}]}
document = {"role": "user", "content": [{"type": "document", "source": source}]}
ATTEMPTS = {
    "web_fetch_tool": {"tools": [{"type": "web_fetch_20260209", "name": "web_fetch"}]},
    "web_search_tool": {"tools": [{"type": "web_search_20260209", "name": "web_search"}]},
    "code_execution_tool": {"tools": [{"type": "code_execution_20260521", "name": "run"}]},
    "remote_mcp_server": {"mcp_servers": [{"type": "url", "url": SINK, "name": "sink"}]},
    "server_container": {"container": {"skills": []}},
    "image_url_source": {"messages": [image]},
    "document_url_source": {"messages": [document]},
    "unapproved_model": {"model": "claude-unapproved"},
    "output_over_bound": {"max_tokens": 10_000_000},
}
results = {name: post({**plain, **change}) for name, change in ATTEMPTS.items()}
results["unapproved_beta"] = post(plain, {"anthropic-beta": "mcp-client-2025-11-20"})
with open("forge-results.json", "w") as stream:
    json.dump(results, stream, indent=2)
