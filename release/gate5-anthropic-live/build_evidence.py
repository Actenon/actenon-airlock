"""Build the Gate 5 evidence package from the untouched live-anthropic directory."""
import base64, hashlib, json, shutil, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SRC, OUT = Path(sys.argv[1]), Path(sys.argv[2])
TRIALS = ["baseline-run", "protected-run", "adversarial-baseline", "adversarial-protected"]
canon = lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
b64u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def verify(d):
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(json.loads((d / "public-key.json").read_text())["key"], validate=True))
    raw = (d / "receipts.jsonl").read_bytes(); lines = raw.splitlines(); prev = None
    for line in lines:
        row = json.loads(line); sig = row.pop("signature")
        assert row["schema"] == "actenon-airlock/receipt/v1" and sig["algorithm"] == "EdDSA" and row.get("prev") == prev
        pub.verify(b64u(sig["value"]), b"actenon-airlock/receipt/v1\n" + canon(row)); prev = hashlib.sha256(line).hexdigest()
    cp = json.loads((d / "checkpoint.json").read_text())
    pub.verify(base64.b64decode(cp["signature"]), b"actenon-airlock/journal-checkpoint/v1\n" + canon(cp["payload"]))
    n = cp["payload"]["journal_entries"]
    anchored = n == len(lines) and hashlib.sha256(lines[n - 1]).hexdigest() == cp["payload"]["chain_head_sha256"]
    return {"verifier": "standalone Ed25519 (stdlib + cryptography; no Airlock imports)", "receipts": len(lines),
            "signatures_and_chain": "ok", "checkpoint_signature": "ok", "checkpoint_entries": n,
            "anchored": anchored, "trusted_key": "public-key.json beside the journal (no earlier out-of-band pin)",
            "public_key_sha256": sha(d / "public-key.json")}

def published(rel):
    if rel.parts[0] not in TRIALS: return None
    name = rel.name
    if len(rel.parts) == 2 and name in ("result.json", "receipts.jsonl", "checkpoint.json", "public-key.json", "sink.json"):
        return rel
    if name == "boundary.json" and "project" in rel.parts and "key.json" not in name:
        return Path(rel.parts[0]) / "boundary.json"
    return None

def reason(rel):
    if "local" in rel.parts and rel.name in ("key.json", "grant-key.json"): return "private signing key"
    if rel.name == "agent.log": return "agent transcript (model output, prompts)"
    if "baseline-workspace" in rel.parts or "workspace" in rel.parts: return "agent workspace copy"
    if "project" in rel.parts: return "supervisor project state (holds private keys; not needed for verification)"
    return "not required for verification"

if OUT.exists(): shutil.rmtree(OUT)
(OUT / "trials").mkdir(parents=True)
manifest = []
for p in sorted(SRC.rglob("*")):
    if not p.is_file() or p.is_symlink(): continue
    rel = p.relative_to(SRC); dest = published(rel)
    entry = {"path": str(rel), "sha256": sha(p), "bytes": p.stat().st_size}
    if dest is not None:
        target = OUT / "trials" / dest; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(p, target)
        entry["published_as"] = str(Path("trials") / dest)
    else:
        entry["excluded"] = reason(rel)
    manifest.append(entry)
summary = {}
for t in TRIALS:
    d = SRC / t; r = json.loads((d / "result.json").read_text()); v = verify(d)
    (OUT / "trials" / t / "verification.json").write_text(json.dumps(v, indent=2) + "\n")
    score = r.get("score") or r["utility"]["score"]
    summary[t] = {"mode": r["mode"], "evidence_class": r["evidence_class"], "agent_exit": r["agent_exit"],
                  "runner_exit_self_reported": r["runner_exit"], "visible": score["visible"]["summary"], "hidden": score["hidden"]["summary"],
                  "tests_modified_by_agent": score["tests_modified_by_agent"],
                  "patched_files": [l.split(" b/")[-1] for l in r["source_patch"].splitlines() if l.startswith("diff --git")],
                  "inference": r["inference"], "estimated_microusd": r["accounting"]["estimated_microusd"],
                  "identity": {k: r["identity"][k] for k in ("source_commit", "source_digest", "image", "model", "prices", "run_usd")},
                  "containment": ({k: r["containment"][k] for k in ("classification", "hook_executed", "hook_outcomes", "agent_requests_count", "referee_requests_count", "canary_exfiltrated")} | {"hook_sha256": r["containment"]["hook_metadata"]["hook_sha256"], "positive_control_status": r["containment"]["positive_control"]["status"]}) if "containment" in r else None,
                  "journal": v}
(OUT / "MANIFEST.json").write_text(json.dumps({"schema": "actenon-airlock/gate5-evidence-manifest/v1", "source_directory": "live-anthropic (owner machine)", "files": manifest}, indent=1) + "\n")
(OUT / "trials-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(len(manifest), "files hashed;", sum("published_as" in m for m in manifest), "published")
print("excluded reasons:", sorted({m["excluded"] for m in manifest if "excluded" in m}))
