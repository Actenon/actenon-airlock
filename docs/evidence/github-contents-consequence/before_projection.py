"""Negative control against the existing generic HTTP effect projection."""
import hashlib
import json
from types import SimpleNamespace

from actenon_protocol.effects import effect_identity

from actenon_airlock.broker import Broker

broker = Broker.__new__(Broker)
broker.effect_namespace = "disposable-repository-owner"
body = b'{"branch":"review","content":"cGF0Y2gK","message":"publish reviewed patch"}'
identities = []
for trace in ("attempt-A", "attempt-B"):
    intent = SimpleNamespace(
        action=SimpleNamespace(capability="github.contents.write", parameters={
            "method": "PUT", "body_sha256": hashlib.sha256(body).hexdigest(),
            "headers_effect_sha256": hashlib.sha256(json.dumps({"x-trace-id": trace}).encode()).hexdigest(),
        }),
        target=SimpleNamespace(resource_type="http", resource_id="https://api.github.com/repos/acme/demo/contents/patches/fix.patch"),
    )
    identities.append(effect_identity(broker._http_effect_descriptor(intent)))
print(json.dumps({"same_reviewed_create": True, "only_trace_changed": True, "identities": identities}, indent=2))
assert identities[0] == identities[1], "generic header-byte projection resets identity for the same GitHub consequence"
