"""Reproducible receipt timings; fixture construction is excluded from timings."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import multiprocessing as mp
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

from actenon.proof.signers.base import b64url_encode
from actenon_permit.ed25519_signer import load_ed25519_keypair
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from actenon_airlock.common import canonical
from actenon_airlock.state import RECEIPT_DOMAIN, RECEIPT_SCHEMA, State, verify_receipt_lines


def fixture(root, count):
    state = State(root)
    state.initialize()
    key = load_ed25519_keypair(state.key_path)
    signer = Ed25519PrivateKey.from_private_bytes(key.private_key_bytes)
    prev, lines = None, []
    for index in range(count):
        value = {
            "schema": RECEIPT_SCHEMA,
            "id": f"fixture-{index}",
            "decision": "DENY",
            "action": "benchmark",
            "target": "owned-fixture",
            "execution_occurred": False,
            "signer_key_id": key.key_id,
            "prev": prev,
            "detail": "x" * 256,
        }
        value["signature"] = {
            "algorithm": "EdDSA",
            "key_id": key.key_id,
            "encoding": "base64url",
            "value": b64url_encode(signer.sign(RECEIPT_DOMAIN + canonical(value))),
        }
        line = canonical(value)
        prev = hashlib.sha256(line).hexdigest()
        lines.append(line)
    state.receipts_path.write_bytes(b"\n".join(lines) + b"\n")
    assert verify_receipt_lines(lines, base64.b64encode(key.public_key_bytes).decode())["ok"]
    return state


def worker(root, ready, start, queue, count):
    try:
        state = State(Path(root))
        ready.put(True)
        if not start.wait(60):
            raise RuntimeError("barrier timeout")
        times = []
        for index in range(count):
            before = time.perf_counter()
            state.receipt(
                {"id": f"concurrent-{mp.current_process().name}-{index}", "decision": "DENY"}
            )
            times.append(time.perf_counter() - before)
        queue.put({"times": times})
    except Exception as exc:
        queue.put({"error": repr(exc)})


def summary(values):
    ordered = sorted(values)
    return {
        "count": len(values),
        "median_s": statistics.median(values),
        "p95_s": ordered[min(len(values) - 1, int(0.95 * len(values)))],
        "total_s": sum(values),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sizes", nargs="+", type=int, default=[100, 1000, 10000])
    parser.add_argument("--append-count", type=int, default=6)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    import actenon_airlock.state as implementation

    results = {
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "state_source_sha256": hashlib.sha256(
            Path(implementation.__file__).read_bytes()
        ).hexdigest(),
        "method": "Real Ed25519 chains, fsync append, process-shared flock; no provider calls",
        "cases": [],
    }
    for size in args.sizes:
        with tempfile.TemporaryDirectory(prefix="airlock-journal-bench-") as directory:
            state = fixture(Path(directory), size)
            byte_count = state.receipts_path.stat().st_size
            before = time.perf_counter()
            assert state.verify_receipts()["ok"]
            verify_time = time.perf_counter() - before
            times = []
            for index in range(args.append_count):
                before = time.perf_counter()
                state.receipt({"id": f"serial-{index}", "decision": "DENY"})
                times.append(time.perf_counter() - before)
            ctx = mp.get_context("spawn")
            ready, queue, start = ctx.Queue(), ctx.Queue(), ctx.Event()
            workers = [
                ctx.Process(target=worker, args=(directory, ready, start, queue, 4))
                for _ in range(args.workers)
            ]
            try:
                for proc in workers:
                    proc.start()
                for _ in workers:
                    assert ready.get(timeout=60)
                before = time.perf_counter()
                start.set()
                replies = [queue.get(timeout=180) for _ in workers]
                wall = time.perf_counter() - before
                for proc in workers:
                    proc.join(10)
                    assert proc.exitcode == 0
                assert all("error" not in reply for reply in replies), replies
            finally:
                for proc in workers:
                    if proc.is_alive():
                        proc.kill()
                        proc.join(10)
                ready.close()
                queue.close()
            checked = state.verify_receipts()
            assert (
                checked["ok"] and checked["receipts"] == size + args.append_count + 4 * args.workers
            )
            case = {
                "initial_rows": size,
                "initial_bytes": byte_count,
                "full_verify_s": verify_time,
                "cold_append_s": times[0],
                "warm_append": summary(times[1:]),
                "concurrent": summary([v for r in replies for v in r["times"]]),
                "concurrent_wall_s": wall,
                "concurrent_writers": args.workers,
                "final_integrity": checked["ok"],
                "final_rows": checked["receipts"],
            }
            results["cases"].append(case)
            print(json.dumps(case), flush=True)
            args.output.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
