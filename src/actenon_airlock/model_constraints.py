"""Narrow reviewed HTTP authority to a text-inference transport.

This does not create or classify authority. Scan's SDK route metadata supplies
the transport format; Scan/Permit/Kernel still name and enforce the HTTP power.
"""

from urllib.parse import urlsplit

from actenon_scan.authority import sdk

from .common import AirlockError, validate_url

DEFAULT_ENDPOINTS = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/messages",
}


def endpoint(profile):
    if not isinstance(profile, dict):
        raise AirlockError("Model constraint must be an object")
    provider = profile.get("provider")
    if provider not in DEFAULT_ENDPOINTS:
        raise AirlockError("Unsupported text inference format")
    raw = profile.get("endpoint", DEFAULT_ENDPOINTS[provider])
    if not isinstance(raw, str):
        raise AirlockError("Model endpoint must be an exact URL")
    value = validate_url(raw)
    parsed = urlsplit(value)
    if parsed.query or parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1"}:
        raise AirlockError("Model endpoint requires HTTPS or a literal loopback HTTP address")
    return value


def validate_profile(profile):
    endpoint(profile)
    if set(profile) - {
        "provider",
        "endpoint",
        "models",
        "max_output_tokens",
        "read_timeout_seconds",
    }:
        raise AirlockError("Unknown model constraint")
    models = profile.get("models")
    if (
        not isinstance(models, list)
        or not models
        or any(
            not isinstance(model, str)
            or not model
            or model.strip() != model
            or model == "*"
            or any(ord(c) < 32 for c in model)
            for model in models
        )
    ):
        raise AirlockError("Models must be a non-empty list of exact names")
    bound = profile.get("max_output_tokens")
    if type(bound) is not int or not 1 <= bound <= 4096:
        raise AirlockError("Invalid approved model output bound")
    timeout = profile.get("read_timeout_seconds", 30)
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise AirlockError("Model read timeout must be between 1 and 600 seconds")
    return profile


def scan_transports(current):
    """Map native Scan SDK evidence to supported wire formats, never new powers.

    Unsupported SDK effects (responses with remote tools, embeddings, images,
    etc.) remain refused rather than falling through to generic HTTP authority.
    """
    routes = {}
    for constructor in {*sdk.LLM_CLIENTS, "openai", "anthropic"}:
        family = constructor if constructor in sdk.LLM_METHODS else constructor.split(".")[0]
        for method, route in sdk.LLM_METHODS.get(family, {}).items():
            format_name = "unsupported"
            if route == ("post", "/chat/completions") and family in {
                "openai",
                "langchain_openai.ChatOpenAI",
            }:
                format_name = "openai"
            elif route == ("post", "/v1/messages") and family in {
                "anthropic",
                "langchain_anthropic.ChatAnthropic",
            }:
                format_name = "anthropic"
            routes[constructor + "." + method] = format_name
    transports = {}
    for entry in current["entries"]:
        format_name = routes.get(entry.get("via"))
        if format_name is not None:
            url = entry["transport"]
            if url in transports and transports[url] != format_name:
                format_name = "unsupported"
            transports[url] = format_name
    return transports
