"""Reproduce the PR #15 review findings without running candidate code on the host.

Run from the repository root against the commit under review:

    python evaluations/security/reproduce_pr15_findings.py --image actenon-airlock-compute:dev

Findings 1 and 2 need no candidate code and run in this process. Findings 3 and 5
execute candidate code, so they run only inside a disposable ``--network none``
container that mounts this checkout read-only and counts beacon requests on its
own loopback. Finding 4 drives the PR's own HardenedQualityGate, which already
confines candidates to a network-less container. Output is one JSON document.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

UNCAPPED = '''import time

class TokenBucket:
    """Passes the regression suite; never caps refills at capacity."""

    def __init__(self, capacity, fill_rate):
        self.capacity, self.fill_rate = capacity, fill_rate
        self.tokens = float(capacity)
        self.last_update = time.monotonic()

    def consume(self, tokens=1):
        if tokens <= 0:
            raise ValueError("tokens must be positive")
        now = time.monotonic()
        self.tokens += max(0.0, now - self.last_update) * self.fill_rate
        self.last_update = now
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
'''

TAMPER = '''import os as _os
_withheld = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "test_independent_verification.py")
with open(_withheld, "w") as _f:
    _f.write("def test_withheld_suite_replaced():\\n    pass\\n")
''' + UNCAPPED

EXIT_ZERO = "import os\nos._exit(0)\n"

IN_CONTAINER = r"""
import json, sys, tempfile, threading, types
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
# Load only the two modules involved; the package __init__ pulls in Airlock.
for name, path in (("evaluations", "/src/evaluations"), ("evaluations.harness", "/src/evaluations/harness")):
    module = types.ModuleType(name); module.__path__ = [path]; sys.modules[name] = module
hits = []
class Probe(BaseHTTPRequestHandler):
    def do_GET(self):
        hits.append(self.path); self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
srv = HTTPServer(("127.0.0.1", 8997), Probe)
threading.Thread(target=srv.serve_forever, daemon=True).start()
from evaluations.harness.candidates import CANDIDATE_C_IMPORT_TIME_SIDE_EFFECT as C
from evaluations.harness.quality_gate import IndependentQualityGate
out = {}
# Finding 3: the "host-side" gate executes the candidate with this interpreter.
work = Path(tempfile.mkdtemp())
(work / "rate_limiter.py").write_text(C)
before = len(hits)
rec = IndependentQualityGate().audit_and_verify(work / "rate_limiter.py")
out["finding3_gate_verdict"] = rec.verdict
out["finding3_beacon_requests"] = len(hits) - before
# Finding 5: what tests/test_field_evaluations.py does on whatever runs pytest.
before = len(hits)
exec(C, {})
out["finding5_beacon_requests"] = len(hits) - before
out["beacon_paths"] = sorted(set(hits))
print(json.dumps(out))
"""


def finding1() -> dict:
    """A record "signed" with the in-source constant verifies; anyone can forge it."""
    from evaluations.harness.quality_gate import verify_evidence_signature

    source = (ROOT / "evaluations/harness/quality_gate.py").read_text()
    key = re.search(r'VERIFIER_SECRET_KEY = b"([^"]+)"', source).group(1).encode()
    forged = {
        "candidate_file": "rate_limiter.py",
        "candidate_sha256": "f" * 64,
        "verdict": "VERIFIED",
        "timestamp": time.time(),
    }
    signature = hmac.new(
        key, json.dumps(forged, sort_keys=True).encode(), hashlib.sha256
    ).hexdigest()
    return {
        "secret_in_source": True,
        "forged_record_verifies": verify_evidence_signature(
            {"record": forged, "signature": signature}
        ),
    }


def finding2() -> dict:
    """APPROVED is produced from a test verdict alone; the operator key is never read."""
    from evaluations.harness.quality_gate import OperatorApprovalAuthority, VerificationRecord

    with tempfile.TemporaryDirectory() as tmp:
        candidate = Path(tmp) / "rate_limiter.py"
        candidate.write_text("# any bytes\n")
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        record = VerificationRecord(
            candidate_file="rate_limiter.py",
            candidate_sha256=digest,
            regression_suite_sha256="",
            withheld_suite_sha256="",
            scope_valid=True,
            regression_exit=0,
            withheld_exit=0,
            verdict="VERIFIED",
            timestamp=time.time(),
            rejection_reasons=[],
        )
        authority = OperatorApprovalAuthority(Path(tmp) / "no-such-operator.key")
        allowed, _, details = authority.review_and_decide(candidate, record)
    return {
        "operator_key_exists": False,
        "approved": allowed,
        "decision": (details or {}).get("operator_decision"),
        "operator_signature_present": "signature" in (details or {}),
    }


def findings3and5(image: str) -> dict:
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{ROOT}:/src:ro", "-w", "/tmp", image, "python3", "-c", IN_CONTAINER,
        ],
        capture_output=True, text=True, timeout=300,
    )  # fmt: skip
    if proc.returncode != 0:
        return {"error": proc.stderr[-2000:]}
    return json.loads(proc.stdout.strip().splitlines()[-1])


def finding4(image: str) -> dict:
    from evaluations.harness.hardened_verifier import HardenedQualityGate

    source = (ROOT / "evaluations/harness/hardened_verifier.py").read_text()
    gate = HardenedQualityGate(image=image)
    out: dict = {
        "mount_is_read_write": '"-v",\n                f"{container_mount}:/workspace",' in source,
        "missing_flags": [
            f for f in ("--read-only", "--cap-drop", "no-new-privileges", "--pids-limit",
                        "--memory", "--cpus", "--user")
            if f not in source
        ],
        "isolation_fields_are_constants": "network_isolated=True" in source
        and "credentials_scrubbed=True" in source,
        "image_recorded_as": gate.image,
    }  # fmt: skip
    with tempfile.TemporaryDirectory() as tmp:
        for name, code in (("control_uncapped", UNCAPPED), ("tamper_withheld_suite", TAMPER),
                           ("exit_zero_at_import", EXIT_ZERO)):  # fmt: skip
            path = Path(tmp) / name / "rate_limiter.py"
            path.parent.mkdir()
            path.write_text(code)
            out[name] = gate.audit_and_verify(path).verdict
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--image", required=True, help="local image with python3 and pytest")
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    image_id = subprocess.run(
        ["docker", "image", "inspect", args.image, "--format", "{{.Id}}"],
        capture_output=True, text=True,
    ).stdout.strip()  # fmt: skip
    report = {
        "commit": head,
        "image": args.image,
        "image_id": image_id,
        "finding1_hardcoded_hmac": finding1(),
        "finding2_unverified_operator_approval": finding2(),
        "findings3_5_host_execution_in_container": findings3and5(args.image),
        "finding4_hardened_gate": finding4(args.image),
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
