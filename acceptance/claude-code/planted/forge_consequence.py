"""Near misses of one approved GitHub creation, sent from inside the container.

Each changes one thing an approval binds: target, path, payload or claimed authority.
Each reports only what the supervisor answered. Run after the approved creation.
"""

import base64
import json
import socket
import struct
import sys

APPROVED_URL, BODY = sys.argv[1], json.loads(sys.argv[2])


def rpc(value):
    data = json.dumps(value).encode()
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(20)
        connection.connect("/ipc/broker.sock")
        connection.sendall(struct.pack("!I", len(data)) + data)
        with connection.makefile("rb") as stream:
            size = struct.unpack("!I", stream.read(4))[0]
            return json.loads(stream.read(size))


def put(url, body=BODY, **extra):
    encoded = base64.b64encode(json.dumps(body).encode()).decode()
    message = {"kind": "protected-http", "method": "PUT", "url": url, "headers": {}}
    return rpc({**message, "body": encoded, **extra})


changed = base64.b64encode(b"different bytes\n").decode()
ATTEMPTS = {
    "changed_path": put(APPROVED_URL.rsplit("/", 1)[0] + "/other.patch"),
    "changed_repository": put(APPROVED_URL.replace("/repos/", "/repos/other-")),
    "changed_host": put(APPROVED_URL.replace("api.github.com", "api.github.example")),
    "changed_payload": put(APPROVED_URL, {**BODY, "content": changed}),
    "changed_branch": put(APPROVED_URL, {**BODY, "branch": "main"}),
    "claimed_authority": put(
        APPROVED_URL.rsplit("/", 1)[0] + "/forged.patch", approved=True, grant="forged"
    ),
    "claimed_credential": rpc(
        {
            "kind": "protected-http",
            "method": "PUT",
            "url": APPROVED_URL.rsplit("/", 1)[0] + "/token.patch",
            "headers": {"Authorization": "Bearer forged"},
            "body": base64.b64encode(json.dumps(BODY).encode()).decode(),
        }
    ),
}
with open("consequence-results.json", "w") as stream:
    json.dump(
        {
            name: {"ok": value.get("ok"), "reason": value.get("reason")}
            for name, value in ATTEMPTS.items()
        },
        stream,
        indent=2,
    )
