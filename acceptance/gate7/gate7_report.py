"""Gate 7 results view: what each agent was asked, did, was allowed and was refused.

Built only from each run's result.json and the signed consequence report
(``airlock explain``); it adds no claim of its own. A rehearsal says so on every
row: a scripted model proves the plumbing, never the agent's autonomy.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _title(case_id: str) -> str:
    first = (HERE / "issues" / f"{case_id}.md").read_text().splitlines()[0]
    return first.lstrip("# ").strip()


def _row(result: dict) -> list[str]:
    score = result["score"]
    consequence = result.get("consequence") or {}
    effect = "none attempted"
    if consequence.get("effect_id"):
        readback = consequence.get("independent_readback", {})
        held = (
            "held AMBIGUOUS"
            if any(
                c.get("control") == "approved-publish" and c.get("status") == "AMBIGUOUS"
                for c in consequence.get("controls", [])
            )
            else "held unconfirmed"
        )
        effect = (
            f"1 reviewed GitHub file creation; {held} until readback; "
            f"independent readback {'CONFIRMED' if readback.get('confirmed') else 'NOT confirmed'}"
        )
    refused = [
        c["control"] for c in consequence.get("controls", []) if c.get("status") == "REFUSED"
    ]
    if result.get("spend_bound_refusals"):
        refused.append(f"{len(result['spend_bound_refusals'])} model call(s) at the spend bound")
    uncertain = []
    if result["inference"]["unconfirmed"]:
        uncertain.append(f"{result['inference']['unconfirmed']} model call(s) unconfirmed")
    if result["evidence_integrity"]["unresolved_effects"]:
        uncertain.append("unresolved effects")
    if result["evidence_class"] != "frozen-live":
        uncertain.append("scripted model: plumbing only, not autonomy")
    return [
        f"{result['capability']}. {_title(result['case'])}",
        result["mode"],
        ", ".join(score["source_files_changed"]) or "nothing",
        "yes" if score["passed"] else "no",
        "; ".join(result.get("powers_authorised", []))
        + (" + one reviewed GitHub create" if consequence.get("effect_id") else ""),
        ", ".join(refused) or "none needed",
        effect,
        "; ".join(uncertain) or "nothing",
        f"**{result['verdict']}**",
    ]


def render(evidence: Path) -> str:
    results = sorted(
        (json.loads(p.read_text()) for p in evidence.glob("*/result.json")),
        key=lambda r: (r["capability"], r["mode"]),
    )
    head = [
        "Case",
        "Mode",
        "What the agent changed",
        "Task done (hidden tests)",
        "Powers authorised",
        "Refused",
        "External consequence",
        "Still uncertain",
        "Verdict",
    ]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    lines += ["| " + " | ".join(c.replace("|", "\\|") for c in _row(r)) + " |" for r in results]
    classes = sorted({r["evidence_class"] for r in results})
    return "\n".join(
        [
            "# Gate 7 results",
            "",
            f"Evidence class: {', '.join(classes)}. Each row is one run; a case's protected row decides it, "
            "and its baseline row shows whether the same task succeeds without Airlock.",
            "",
            *lines,
            "",
            "Per run: `result.json` (scores, inference, accounting), `agent.patch` (the exact change), "
            "`receipts.jsonl` + `checkpoint.json` + `public-key.json` (verify with "
            "`airlock verify-evidence`), and for cases 9-10 `CONSEQUENCE.md` (`airlock explain`).",
            "",
        ]
    )
