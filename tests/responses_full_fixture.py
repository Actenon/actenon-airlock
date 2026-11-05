"""Documented supported response subset; never reconstructed live values."""

from responses_tool_echo_fixture import EIGHT, echo, stream


def full_response(policy="enabled"):
    seq = stream(echo(EIGHT))
    for event in seq:
        if "response" in event:
            event["response"].update(
                conversation=None,
                moderation=None,
                prompt_cache_options=None,
                image={"context_compression": policy},
            )
    final = seq[-1]["response"]
    final["completed_at"] = 1793740801
    final["usage"]["input_tokens_details"]["cache_write_tokens"] = 0
    final["usage"]["output_tokens_details"] = {"reasoning_tokens": 0}
    return seq
