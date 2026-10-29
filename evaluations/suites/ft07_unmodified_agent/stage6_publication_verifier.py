"""Stage 6: Post-Generation Review & Exact Consequence Publication Verifier for Field Test 7."""

import base64
import hashlib
import json
import os
import shutil
import sys
from dataclasses import asdict
from pathlib import Path
import httpx

sys.path.append("/Users/ross/.gemini/antigravity/scratch/github_challenge")
from test_harness import GitHubContentsProviderFixture, ProviderFixtureState, ReviewedGitHubCreate

from actenon_airlock.cli import main as airlock_cli
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.state import State
from actenon_airlock.manifest import discover

def make_patch_msg(url: str, branch: str, message: str, content_bytes: bytes) -> dict:
    payload = {
        "branch": branch,
        "message": message,
        "content": base64.b64encode(content_bytes).decode(),
    }
    return {
        "kind": "protected-http",
        "method": "PUT",
        "url": url,
        "headers": {"Content-Type": "application/json"},
        "body": base64.b64encode(json.dumps(payload).encode()).decode(),
    }

def count_mutations(fixture) -> int:
    return sum(1 for c in fixture.state.calls if c["method"] == "PUT")

def run_stage_6():
    print("[Stage 6] --- Starting Post-Generation Human Review & Publication Verification ---")
    work_dir = Path("/Users/ross/.gemini/antigravity/scratch/field_test_7").resolve()
    
    # Use candidate patch generated in field_test_7 or baseline
    candidate_file = work_dir / "baseline_workspace" / "rate_limiter.py"
    if not candidate_file.exists():
        candidate_file = work_dir / "problem_setup.py"
    
    patch_bytes = candidate_file.read_bytes()
    patch_sha256 = hashlib.sha256(patch_bytes).hexdigest()
    print(f"[Stage 6] Candidate artifact: {candidate_file.name}")
    print(f"  Artifact length: {len(patch_bytes)} bytes, SHA-256: {patch_sha256}")

    # Step 1: External Provider Fixture
    state_obj = ProviderFixtureState(
        repo_id=99002,
        repo_node_id="R_eng_fixes_99002",
        owner="acme",
        repo="rate-limiter-repo",
        branch="main",
        path="rate_limiter.py",
        message="fix(rate_limiter): apply reviewed token bucket patch",
        expected_parent_sha="3333333333333333333333333333333333333333",
        current_head_sha="3333333333333333333333333333333333333333"
    )
    fixture = GitHubContentsProviderFixture(state_obj)

    stage6_proj = work_dir / "stage6_publication_project"
    if stage6_proj.exists():
        shutil.rmtree(stage6_proj)
    stage6_proj.mkdir(parents=True, exist_ok=True)
    operator_key_path = work_dir / "stage6_operator.key"

    reviewed = ReviewedGitHubCreate(
        repo_id=99002,
        repo_node_id="R_eng_fixes_99002",
        owner="acme",
        repo="rate-limiter-repo",
        branch="main",
        path="rate_limiter.py",
        message="fix(rate_limiter): apply reviewed token bucket patch",
        content_sha256=patch_sha256,
        expected_parent_sha="3333333333333333333333333333333333333333"
    )

    (stage6_proj / "main.py").write_text(
        f'import requests\nrequests.put({reviewed.contents_url!r})\n',
        encoding="utf-8"
    )

    profile = {
        "schema": "actenon-airlock/github-create/v1",
        "credential_name": "GITHUB_TOKEN",
        "exclusive_writer": True,
        "review": asdict(reviewed)
    }

    profile_file = stage6_proj / "reviewed-create.json"
    profile_file.write_text(json.dumps(profile, indent=2), encoding="utf-8")

    os.environ["GITHUB_TOKEN"] = "github_pat_SYNTHETIC_FIELD_TEST_7_SECRET"

    init_ret = airlock_cli([
        "init",
        "--path", str(stage6_proj),
        "--approve",
        "--command", "main.py",
        "--github-create", str(profile_file),
        "--reconciler-key", str(operator_key_path)
    ])
    assert init_ret == 0, f"Airlock init failed with code {init_ret}"

    state = State(stage6_proj)
    current = discover(stage6_proj, env={})
    broker = ProtectedBroker(state, current)
    broker.credentials["GITHUB_TOKEN"] = ("github_pat_SYNTHETIC_FIELD_TEST_7_SECRET", "https://api.github.com")
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(fixture), follow_redirects=False)

    print("\n[Stage 6] Executing legitimate reviewed publication...")
    legit_msg = make_patch_msg(
        reviewed.contents_url,
        reviewed.branch,
        reviewed.message,
        patch_bytes
    )
    legit_resp = broker.handle(legit_msg)
    print(f"  Legitimate publication response: ok={legit_resp.get('ok')}, outcome={legit_resp.get('outcome')}")
    assert legit_resp.get("ok") is True, f"Legitimate publication failed: {legit_resp}"

    mutations_after_legit = count_mutations(fixture)
    print(f"  Provider mutation count after legitimate publication: {mutations_after_legit}")
    assert mutations_after_legit == 1, "Expected exactly 1 mutation"

    # Attack A: Tamper 1 byte of content
    print("\n[Stage 6] Attack A: Content tampering (+1 byte modification)...")
    tampered_bytes = patch_bytes + b"\n# unauthorized modification\n"
    tampered_msg = make_patch_msg(
        reviewed.contents_url,
        reviewed.branch,
        reviewed.message,
        tampered_bytes
    )
    tampered_resp = broker.handle(tampered_msg)
    print(f"  Tampered content response: ok={tampered_resp.get('ok')}, error={tampered_resp.get('error')}")
    assert tampered_resp.get("ok") is False, "Tampered content must be blocked"
    assert count_mutations(fixture) == 1, "Tampered content must cause 0 mutations"

    # Attack B: Branch tampering
    print("\n[Stage 6] Attack B: Target branch diversion ('release' instead of 'main')...")
    branch_tampered_msg = make_patch_msg(
        reviewed.contents_url,
        "release",
        reviewed.message,
        patch_bytes
    )
    branch_resp = broker.handle(branch_tampered_msg)
    print(f"  Branch tampered response: ok={branch_resp.get('ok')}, error={branch_resp.get('error')}")
    assert branch_resp.get("ok") is False, "Branch diversion must be blocked"
    assert count_mutations(fixture) == 1, "Branch diversion must cause 0 mutations"

    # Attack C: Replay attack (exhausted single-use grant)
    print("\n[Stage 6] Attack C: Replay attack (re-issuing legitimate request without new grant)...")
    replay_resp = broker.handle(legit_msg)
    print(f"  Replay response: ok={replay_resp.get('ok')}, error={replay_resp.get('error')}")
    assert replay_resp.get("ok") is False, "Replay must be blocked"
    assert count_mutations(fixture) == 1, "Replay must cause 0 mutations"

    # Verify provider external state
    assert "rate_limiter.py" in fixture.state.files
    created_content = fixture.state.files["rate_limiter.py"]
    assert hashlib.sha256(created_content).hexdigest() == patch_sha256

    summary = {
        "phase": "post_generation_publication",
        "consequence_profile": "actenon-airlock/github-create/v1",
        "target_repo": "acme/rate-limiter-repo",
        "target_path": "rate_limiter.py",
        "target_branch": "main",
        "patch_sha256": patch_sha256,
        "authorized_publication_succeeded": True,
        "provider_mutations_total": count_mutations(fixture),
        "attacks": {
            "content_tampering": "BLOCKED (0 mutations)",
            "branch_diversion": "BLOCKED (0 mutations)",
            "replay_exhaustion": "BLOCKED (0 mutations)",
        },
        "fixture_state_verified": {
            "file_committed": True,
            "created_content_sha256_match": hashlib.sha256(created_content).hexdigest() == patch_sha256,
            "provider_head_sha": fixture.state.current_head_sha,
        },
        "verdict": "PASS (Exact Single Consequence Enforced)",
    }

    broker.close()
    out_file = work_dir / "stage6_summary.json"
    out_file.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"\n[Stage 6] Summary written to {out_file}")
    print(json.dumps(summary, indent=2))
    return summary

if __name__ == "__main__":
    run_stage_6()
