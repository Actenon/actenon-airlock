"""The user-facing Airlock workflow."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import shlex
import sys
from pathlib import Path

from . import __version__
from .adapters import scope
from .manifest import AirlockError, authority_diff, discover, origin
from .state import State, atomic_json

EXPECTED = {
    "actenon-scan": "1.6.0",
    "actenon-permit": "2.0.0rc1",
    "actenon-kernel": "1.3.0",
    "actenon-protocol": "1.6.0",
}


def render(diff: dict) -> str:
    def safe(value):
        return json.dumps(str(value), ensure_ascii=False)[1:-1]

    lines = ["AIRLOCK AUTHORITY DIFF", ""]
    for sign, name in [("+", "added"), ("-", "removed")]:
        for p in diff[name]:
            lines.extend(
                [
                    f"{sign} {safe(p['action'])} @ {safe(p['resource'])}",
                    f"  Transport: {safe(p['transport'])}",
                    f"  Scope: {safe(scope(p))}",
                ]
            )
    for row in diff["blocked"]:
        lines.append(
            f"! {safe(row['action'])} ({safe(row['file'])}:{row['line']}): {safe(row['reason'])}"
        )
    for row in diff["parse_errors"]:
        lines.append(f"! {safe(row['file'])}: {safe(row['reason'])}")
    model = diff.get("model_constraints", {})
    if model.get("expanded"):
        lines.append("+ Model authority expanded: " + json.dumps(model["after"], sort_keys=True))
    if not any(diff[k] for k in ("added", "removed", "blocked", "parse_errors")) and not model.get(
        "expanded"
    ):
        lines.append("No authority changes.")
    lines.extend(["", "Runtime: " + diff["runtime_status"]])
    return "\n".join(lines)


def render_receipts(result: dict) -> str:
    def safe(value):
        return json.dumps(str(value), ensure_ascii=False)[1:-1]

    lines = [
        "AIRLOCK RECEIPTS",
        f"{result['verified']} of {result['receipts']} verified against .airlock/public-key.json"
        + ("" if result["ok"] else " - VERIFICATION FAILED"),
        "",
    ]
    for item in result["rows"]:
        row = item["row"] if isinstance(item["row"], dict) else {}
        decision = row.get("decision", "?")
        stage = row.get("stage", "")
        head = f"{safe(row.get('timestamp', '?'))}  {decision:<5} {stage:<16}"
        lines.append(f"{head}{safe(row.get('action', '?'))} @ {safe(row.get('target', '?'))}")
        facts = []
        evidence = row.get("evidence")
        if isinstance(evidence, dict):
            facts.append(f"{safe(evidence.get('file'))}:{evidence.get('line')}")
        if decision == "DENY" or stage == "execution-error":
            facts.append("reason: " + safe(row.get("reason", "")))
        facts.append(
            "credential released" if row.get("credential_released") else "no credential released"
        )
        executed = row.get("execution_occurred")
        if row.get("outcome"):
            facts.append("effect: " + safe(row["outcome"]))
        if row.get("effect_id"):
            facts.append(safe(row["effect_id"]))
        if row.get("operator_action") == "reconcile":
            facts.append("observer attestation; no redispatch")
        facts.append(
            {True: "executed", False: "not executed"}.get(
                executed,
                "released; execution unobserved"
                if stage == "released"
                else "execution result unknown",
            )
        )
        if not item["verified"]:
            facts.append("UNVERIFIED: " + safe(item["problem"]))
        lines.append("    " + " | ".join(facts) + f"  [{safe(row.get('id', '?'))}]")
    if not result["rows"]:
        lines.append("No receipts yet.")
    return "\n".join(lines)


def doctor(root: Path):
    from .protected import availability

    checks = []
    for name, expected in EXPECTED.items():
        try:
            actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            actual = "missing"
        checks.append(
            {"component": name, "version": actual, "expected": expected, "ok": actual == expected}
        )
    try:
        from actenon.gate import ActenonGate  # noqa: F401
        from actenon_permit.pdp import PDP  # noqa: F401
        from actenon_scan.authority import extract_authority  # noqa: F401

        checks.append({"component": "integrated interfaces", "ok": True})
    except ImportError:
        checks.append({"component": "integrated interfaces", "ok": False})
    checks.append({"component": "Linux/macOS broker launcher", "ok": os.name == "posix"})
    if (root / ".airlock").exists():
        try:
            State(root).approved()
            checks.append({"component": "local approval signature", "ok": True})
        except AirlockError:
            checks.append({"component": "local approval signature", "ok": False})
    protected = availability()
    return {
        "schema": "actenon-airlock/doctor/v1",
        "checks": checks,
        "guarantees": {"local": "cooperative Python interception", "protected": protected},
        "ok": all(c["ok"] for c in checks),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="See and control the powers of your Python AI agent."
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for cmd in ("init", "diff", "check", "doctor", "run", "receipts", "reconcile"):
        p = sub.add_parser(cmd)
        p.add_argument("--path", type=Path, default=Path.cwd())
        if cmd != "run":
            p.add_argument("--json", action="store_true", help="Print machine-readable JSON")
        if cmd in {"diff", "check"}:
            p.add_argument("--base", help="Compare to the signed approval at this trusted Git ref")
            p.add_argument("--output", type=Path, help="Save JSON authority diff")
            p.add_argument(
                "--github", action="store_true", help="Write GitHub job summary and annotations"
            )
        if cmd == "init":
            p.add_argument(
                "--model", action="append", default=[], help="Approve this exact inference model"
            )
            p.add_argument("--model-provider", choices=("openai", "anthropic"), default="openai")
            p.add_argument("--model-max-tokens", type=int, default=2048)
            p.add_argument(
                "--model-endpoint", help="Exact full inference endpoint also discovered by Scan"
            )
            p.add_argument(
                "--approve",
                action="store_true",
                help="Explicitly approve the displayed resolved powers",
            )
            p.add_argument("--command", help='Python script and arguments, or "-m module"')
            p.add_argument("--credential", action="append", default=[], metavar="NAME=HTTPS_ORIGIN")
            p.add_argument(
                "--reconciler-key",
                type=Path,
                help="Create/load an external operator key; --approve trusts its public key",
            )
        if cmd == "reconcile":
            p.add_argument("effect_id")
            outcome = p.add_mutually_exclusive_group()
            outcome.add_argument("--committed", action="store_true")
            outcome.add_argument("--not-executed", action="store_true")
            p.add_argument(
                "--operator-key", type=Path, help="External approved operator private key"
            )
            p.add_argument(
                "--evidence",
                type=Path,
                help="Provider/operator evidence file (only its hash is recorded)",
            )
            p.add_argument(
                "--approval", type=Path, help="Apply a detached signed reconciliation observation"
            )
            p.add_argument(
                "--output",
                type=Path,
                help="Write a signed observation for review without changing the ledger",
            )
        if cmd == "run":
            p.add_argument(
                "--protected",
                action="store_true",
                help="Require outside-process containment; never downgrade",
            )
            p.add_argument(
                "--image",
                help="Trusted, credential-free local compute image (resolved to immutable ID)",
            )
            p.add_argument(
                "command", nargs=argparse.REMAINDER, help="Python script and arguments after --"
            )
    args = parser.parse_args(argv)
    root = args.path.resolve()
    try:
        if not root.is_dir():
            raise AirlockError("Project directory does not exist")
        if args.cmd == "doctor":
            result = doctor(root)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                for c in result["checks"]:
                    print(
                        ("OK " if c["ok"] else "FAIL ")
                        + c["component"]
                        + (" " + c["version"] if "version" in c else "")
                    )
                print("Candidate dependencies are pinned; registry releases remain pending.")
                print("LOCAL MODE: cooperative Python protection")
                print(
                    "PROTECTED MODE AVAILABLE"
                    if result["guarantees"]["protected"]["available"]
                    else "COOPERATIVE MODE ONLY: " + result["guarantees"]["protected"]["reason"]
                )
            return 0 if result["ok"] else 2
        if args.cmd == "receipts":
            result = State(root).verify_receipts()
            print(json.dumps(result, indent=2) if args.json else render_receipts(result))
            return 0 if result["ok"] else 2
        if args.cmd == "reconcile":
            from .reconciliation import (
                apply_reconciliation,
                load_operator_key,
                operator_identity,
                prepare_reconciliation,
                sign_reconciliation,
            )

            state = State(root)
            request = prepare_reconciliation(state, args.effect_id)
            if args.approval:
                if (
                    args.committed
                    or args.not_executed
                    or args.operator_key
                    or args.evidence
                    or args.output
                ):
                    raise AirlockError("Detached approval cannot be combined with signing options")
                envelope = json.loads(args.approval.read_text())
                if (
                    envelope.get("payload", {}).get("reference", {}).get("effect_id")
                    != args.effect_id
                ):
                    raise AirlockError("Detached approval refers to a different effect")
                result = apply_reconciliation(state, envelope)
            elif args.committed or args.not_executed:
                if not args.operator_key or not args.evidence:
                    raise AirlockError(
                        "Outcome requires an approved --operator-key and --evidence file"
                    )
                private = load_operator_key(state, args.operator_key)
                kid, public = operator_identity(private)
                if state.approved().get("reconciliation_keys", {}).get(kid) != public:
                    raise AirlockError("Operator key is not approved for this project")
                with args.evidence.open("rb") as stream:
                    evidence_hash = hashlib.file_digest(stream, "sha256").hexdigest()
                envelope = sign_reconciliation(
                    request,
                    private,
                    outcome="COMMITTED" if args.committed else "NOT_EXECUTED",
                    evidence_hash=evidence_hash,
                )
                if args.output:
                    atomic_json(args.output, envelope)
                    result = {
                        "signed": True,
                        "applied": False,
                        "effect_id": args.effect_id,
                        "output": str(args.output),
                    }
                else:
                    result = apply_reconciliation(state, envelope)
            else:
                if args.operator_key or args.evidence or args.output:
                    raise AirlockError("Signing options require --committed or --not-executed")
                result = request
            if args.json:
                print(json.dumps(result, indent=2))
            elif result.get("applied"):
                print(f"AIRLOCK RECONCILED {args.effect_id}: {result['outcome']}")
                print("Evidence: authorized observer attestation. No request was redispatched.")
                print("Receipt: " + result["receipt_id"])
                if result.get("receipt_warning"):
                    print(result["receipt_warning"])
            elif result.get("signed"):
                print(
                    "Signed observation saved for review; effect remains held: " + result["output"]
                )
            else:
                print("AIRLOCK EFFECT\n" + json.dumps(result, indent=2))
                print("No state changed. Confirm provider state before selecting an outcome.")
            return 0
        if args.cmd == "run":
            from .broker import launch

            approved = State(root).approved()
            command = args.command
            if command[:1] == ["--"]:
                command = command[1:]
            command = command or approved.get("command", [])
            if not command:
                raise AirlockError(
                    "Set a Python command with airlock init --command 'main.py', or airlock run -- main.py"
                )
            if args.protected:
                from .protected import DEFAULT_IMAGE, launch_protected

                if command[0].endswith(".py") or command[0] == "-m":
                    command = ["python3", *command]
                return launch_protected(root, command, image=args.image or DEFAULT_IMAGE)
            if args.image:
                raise AirlockError("--image requires --protected")
            if command[0] in {"python", "python3", Path(sys.executable).name}:
                command = command[1:]
            return launch(root, command, approved.get("credential_bindings", {}))
        current = discover(root)
        state = State(root)
        if args.cmd == "init":
            state.initialize()
            try:
                before = state.approved()
            except AirlockError:
                if (state.path / "approved.json").exists():
                    raise
                before = {"powers": []}
            bindings = dict(before.get("credential_bindings", {}))
            for binding in args.credential:
                name, sep, url = binding.partition("=")
                if not sep or not name.isidentifier() or not url.startswith("https://"):
                    raise AirlockError("Credential binding must be NAME=HTTPS_ORIGIN")
                bindings[name] = origin(url)
            current["credential_bindings"] = bindings
            current["protected_model"] = dict(before.get("protected_model", {}))
            if args.model_endpoint and not args.model:
                raise AirlockError("--model-endpoint requires --model and a fresh review")
            if args.model:
                from .model_constraints import endpoint, validate_profile

                if not 1 <= args.model_max_tokens <= 4096 or any(
                    not model.strip() for model in args.model
                ):
                    raise AirlockError("Models require names and a token bound between 1 and 4096")
                current["protected_model"] = {
                    "provider": args.model_provider,
                    "models": sorted(set(args.model)),
                    "max_output_tokens": args.model_max_tokens,
                }
                if args.model_endpoint:
                    current["protected_model"]["endpoint"] = args.model_endpoint
                elif before.get("protected_model", {}).get(
                    "provider"
                ) == args.model_provider and before["protected_model"].get("endpoint"):
                    current["protected_model"]["endpoint"] = before["protected_model"]["endpoint"]
                validate_profile(current["protected_model"])
                target = endpoint(current["protected_model"])
                if not any(
                    p["action"] == "http.post" and p["transport"] == target
                    for p in current["powers"]
                ):
                    raise AirlockError(
                        "Model endpoint must be discovered as an exact Scan POST power"
                    )
            current["reconciliation_keys"] = dict(before.get("reconciliation_keys", {}))
            if args.reconciler_key:
                from .reconciliation import load_operator_key, operator_identity

                kid, public = operator_identity(
                    load_operator_key(state, args.reconciler_key, create=True)
                )
                current["reconciliation_keys"][kid] = public
            if args.command:
                current["command"] = shlex.split(args.command)
            else:
                candidates = [
                    name for name in ("main.py", "agent.py", "run.py") if (root / name).is_file()
                ]
                current["command"] = before.get("command") or (
                    candidates[:1] if len(candidates) == 1 else []
                )
            atomic_json(state.path / "proposed.json", current)
            result = authority_diff(before, current)
            print(json.dumps(current, indent=2) if args.json else render(result))
            if not args.json and bindings:
                print("\nCredential origin bindings:")
                for name, url in sorted(bindings.items()):
                    print(f"  {name} -> {url}")
            if not args.json and current["reconciliation_keys"]:
                print("\nReconciliation observer keys (trusted only with --approve):")
                for kid in sorted(current["reconciliation_keys"]):
                    print("  " + kid)
            if not args.json and current["protected_model"]:
                print("\nProtected inference constraint (trusted only with --approve):")
                print(json.dumps(current["protected_model"], sort_keys=True))
            if current["parse_errors"]:
                raise AirlockError("Parse errors prevent approval")
            if args.approve:
                state.approve(current)
                if not args.json:
                    print(
                        f"\nApproved {len(current['powers'])} powers. Unresolved powers remain blocked;"
                        " their calls are denied at runtime with signed receipts."
                    )
            elif not args.json:
                print("\nReview these powers, then run airlock init --approve to activate them.")
            return 0
        before = state.from_git(args.base) if args.base else state.approved()
        if (state.path / "approved.json").exists():
            current["protected_model"] = state.checked_in_approval().get("protected_model", {})
        diff = authority_diff(before, current)
        if args.output:
            atomic_json(args.output, diff, 0o644)
        print(json.dumps(diff, indent=2) if args.json else render(diff))
        if args.github:
            text = render(diff)
            # HTML-escape hostile source filenames/URLs in the Markdown job summary.
            import html

            if os.environ.get("GITHUB_STEP_SUMMARY"):
                with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
                    stream.write(
                        "### Airlock / Authority Review\n\n<pre>" + html.escape(text) + "</pre>\n"
                    )
            if (
                diff["added"]
                or diff["blocked"]
                or diff["parse_errors"]
                or diff["model_constraints"]["expanded"]
            ):
                print(
                    "::error title=Airlock Authority Review::New or unresolved powers remain blocked"
                )
        return (
            2
            if args.cmd == "check"
            and (
                any(diff[k] for k in ("added", "blocked", "parse_errors"))
                or diff["model_constraints"]["expanded"]
            )
            else 0
        )
    except (AirlockError, OSError, ValueError, KeyError) as exc:
        if getattr(args, "json", False):
            print(json.dumps({"error": str(exc), "runtime_status": "BLOCKED"}))
        else:
            print("AIRLOCK BLOCKED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
