"""Authority a person can read: what is granted, and what was found but is not.

Discovery and approval are separate. Scan finds every power in a project's own code.
For a project set up for a protected agent, only the powers the Protected Mode boundary
can ever use are granted: the approved model's exact POST route and the scan power of
each separately reviewed GitHub creation. Everything else is listed as found and not
granted; it would only matter for ``airlock run``, which runs the project's own code on
this machine, and needs ``--grant-discovered`` there.
"""

from __future__ import annotations

from decimal import Decimal

from .manifest import capability


def protected_grants(current: dict) -> tuple[list[dict], list[dict]]:
    """Split discovered powers into (granted, not granted) for a protected agent project."""
    from .github_runtime import review_for, scan_power

    wanted = set()
    model = current.get("protected_model") or {}
    if model:
        from .model_constraints import endpoint

        target = endpoint(model)
        wanted |= {
            capability(p)
            for p in current["powers"]
            if p["action"] == "http.post" and p["transport"] == target
        }
    for profile in current.get("protected_github") or []:
        wanted.add(capability(scan_power(review_for(profile))))
    granted = [p for p in current["powers"] if capability(p) in wanted]
    withheld = [p for p in current["powers"] if capability(p) not in wanted]
    return granted, withheld


def describe(power: dict) -> str:
    action, resource = power["action"], power["resource"]
    return {
        "http.post": f"Send requests to {resource}",
        "github.contents.write": f"Create a file in the GitHub repository {resource}",
        "http.put": f"Write to {resource}",
        "http.get": f"Read from {resource}",
        "process.exec": f"Run the program `{resource}` on this machine",
        "filesystem.write": f"Write the file {resource}",
        "filesystem.delete": f"Delete {resource}",
        "filesystem.read": f"Read the file {resource}",
    }.get(action, f"{action} {resource}")


def _where(current: dict, power: dict) -> str:
    for entry in current.get("entries", []):
        if capability(entry) == capability(power):
            evidence = entry.get("evidence") or {}
            return f"{evidence.get('file')}:{evidence.get('line')}"
    return "your code"


def _usd(microusd: int) -> str:
    return f"${Decimal(microusd) / 1_000_000:.2f}"


def _model_limits(model: dict) -> list[str]:
    """Every bound that is signed with the model grant, in words."""
    out = []
    prices = model.get("price_microusd_per_mtok")
    if prices:
        words = ", ".join(
            f"{name.replace('_', ' ')} {_usd(prices[name])}"
            for name in ("input", "cache_write", "cache_read", "output")
            if name in prices
        )
        out.append(f"Prices for the spend bound, per million tokens: {words}.")
        out.append("Before each call Airlock reserves its worst-case cost, and refuses the call")
        out.append("if that could exceed what is left of the bound.")
    if model.get("max_output_tokens"):
        out.append(f"At most {model['max_output_tokens']} output tokens per call.")
    if model.get("max_input_bytes"):
        out.append(f"At most {model['max_input_bytes'] // 1024} KiB per request.")
    if model.get("anthropic_betas"):
        out.append("Model features allowed: " + ", ".join(model["anthropic_betas"]) + ".")
    if model.get("contract"):
        out.append(f"Request format enforced: {model['contract']}.")
    if model.get("read_timeout_seconds"):
        out.append(f"Each reply must start within {model['read_timeout_seconds']} seconds.")
    return out


def render_review(current: dict, granted: list[dict], withheld: list[dict]) -> str:
    """The review a developer reads before approving, in plain language."""
    lines = ["Authority review", "", "Airlock will grant only this:"]
    model = current.get("protected_model") or {}
    number = 0
    for power in granted:
        number += 1
        if model and power["action"] == "http.post":
            models = ", ".join(model.get("models", []))
            bound = model.get("max_run_microusd")
            limit = f", spending at most {_usd(bound)} per run" if bound else ""
            lines.append(f"  {number}. Send prompts to {models} at {power['resource']}{limit}.")
            lines.append(
                "     The API key stays with Airlock on this machine; the agent never sees it."
            )
            lines += [f"     {line}" for line in _model_limits(model)]
        else:
            lines.append(f"  {number}. {describe(power)}")
    for profile in current.get("protected_github") or []:
        from .github_runtime import review_for

        review = review_for(profile)
        lines.append(
            f"     Exactly one new file: {review.owner}/{review.repo} branch {review.branch}, "
            f"{review.path}, content SHA-256 {review.content_sha256[:12]}…"
        )
    if not granted:
        lines.append("  nothing")
    lines += [
        "",
        "The agent works in a sealed container: no network, no credentials, no home directory.",
    ]
    if withheld:
        lines += ["", f"Found in this project's code but NOT granted ({len(withheld)}):"]
        for power in withheld[:8]:
            lines.append(f"  - {describe(power)}  ({_where(current, power)})")
        if len(withheld) > 8:
            lines.append(f"  - and {len(withheld) - 8} more")
        lines.append("  The agent cannot use these. They only matter if you run your own code with")
        lines.append("  `airlock run`, which asks for them separately with --grant-discovered.")
    blocked = len(current.get("blocked", []))
    if blocked:
        lines.append(
            f"\n{blocked} other call(s) in the code have no exact target and stay blocked."
        )
    lines.append("\nFull internal details: rerun this command with --details")
    return "\n".join(lines)
