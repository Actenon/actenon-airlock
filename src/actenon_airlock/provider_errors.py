"""Failed inference-provider replies: fixed-vocabulary evidence and sanitized relays.

A provider error body is untrusted text. It can echo the supervisor credential
(or a masked fragment the exact-secret redaction cannot recognise), tenant
identifiers, request internals or arbitrary content. Nothing from it is copied:
the signed observation keeps the integer status plus a code or type ONLY when
it exactly matches the allowlists below, and the contained agent receives a
small locally generated error with the same status.

Neither function establishes billing, execution or the absence of either.
Accounting outcomes are decided elsewhere and are unchanged by this module.
"""

from __future__ import annotations

import json

from actenon.core.json import loads_no_duplicate_keys

# Bounded parse: a provider error is small; anything larger is not inspected.
MAX_ERROR_BYTES = 64 * 1024

# OpenAI error codes with public, documented meaning. Presence here grants
# nothing: it only lets a fixed string be recorded instead of "unrecognised".
PROVIDER_ERROR_CODES = frozenset(
    {
        "invalid_api_key",
        "insufficient_quota",
        "rate_limit_exceeded",
        "model_not_found",
        "context_length_exceeded",
        "unsupported_country_region_territory",
        "server_error",
    }
)
# OpenAI `error.type` and Anthropic `error.type` values.
PROVIDER_ERROR_TYPES = frozenset(
    {
        "invalid_request_error",
        "authentication_error",
        "permission_error",
        "not_found_error",
        "rate_limit_error",
        "request_too_large",
        "insufficient_quota",
        "server_error",
        "api_error",
        "overloaded_error",
    }
)
SANITIZED_TYPE = "airlock_provider_error"
SANITIZED_HEADERS = {"content-type": "application/json"}


def _status(value):
    return value if type(value) is int and 100 <= value <= 599 else "invalid"


def _fixed(value, allowed):
    if value is None:
        return None
    if not isinstance(value, str):
        return "invalid"
    return value if value in allowed else "unrecognised"


def status_diagnostic(status, body: bytes) -> dict:
    """Signed-evidence fields for one reply. Only fixed strings and an integer."""
    code = _status(status)
    result = {
        "http_status": code,
        "http_status_class": f"{code // 100}xx" if code != "invalid" else "invalid",
    }
    if code == 200:
        return result
    if not body:
        result["provider_error_body"] = "empty"
        return result
    if len(body) > MAX_ERROR_BYTES:
        result["provider_error_body"] = "oversized"
        return result
    try:
        reply = loads_no_duplicate_keys(body)
        json.dumps(reply, allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        result["provider_error_body"] = "malformed"
        return result
    error = reply.get("error") if isinstance(reply, dict) else None
    if not isinstance(error, dict):
        result["provider_error_body"] = "unexpected-shape"
        return result
    result["provider_error_body"] = "json"
    for name, allowed, field in (
        ("code", PROVIDER_ERROR_CODES, "provider_error_code"),
        ("type", PROVIDER_ERROR_TYPES, "provider_error_type"),
    ):
        value = _fixed(error.get(name), allowed)
        if value is not None:
            result[field] = value
    return result


def sanitized_body(status: int, label: str | None, flavour: str) -> dict:
    """The only error body the contained agent ever sees for a failed reply.

    `label` must already be an allowlisted code (OpenAI) or type (Anthropic);
    anything else is dropped. The message is constant apart from the status.
    """
    message = f"Inference provider returned HTTP {status}; Airlock withheld the provider response."
    if flavour == "anthropic":
        kind = label if label in PROVIDER_ERROR_TYPES else "api_error"
        return {"type": "error", "error": {"type": kind, "message": message}}
    return {
        "error": {
            "message": message,
            "type": SANITIZED_TYPE,
            "param": None,
            "code": label if label in PROVIDER_ERROR_CODES else None,
        }
    }


def sanitized_reply(status, body: bytes, flavour: str) -> tuple[int, dict, bytes]:
    """Status, headers and body to relay instead of a failed provider reply."""
    diagnostic = status_diagnostic(status, body)
    code = status if diagnostic["http_status"] != "invalid" else 502
    label = diagnostic.get(
        "provider_error_type" if flavour == "anthropic" else "provider_error_code"
    )
    content = json.dumps(sanitized_body(code, label, flavour), separators=(",", ":")).encode()
    return code, dict(SANITIZED_HEADERS), content
