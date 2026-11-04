"""Authored Codex-style tool definitions, not recovered live payloads."""

import copy

from test_responses_live_metadata import ALL_ZERO, lifecycle


def function(name="exec_command"):
    return {
        "type": "function",
        "name": name,
        "description": "Synthetic local operation",
        "strict": False,
        "parameters": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
            "additionalProperties": False,
        },
    }


def custom():
    return {
        "type": "custom",
        "name": "apply_patch",
        "description": "Synthetic local patch",
        "format": {"type": "grammar", "syntax": "lark", "definition": 'start: "patch"'},
    }


EIGHT = [
    function(n)
    for n in (
        "exec_command",
        "write_stdin",
        "update_plan",
        "view_image",
        "request_user_input",
        "request_user_input_async",
        "get_goal",
    )
]
EIGHT.append(custom())


def echo(inventory, defaults=True):
    result = copy.deepcopy(inventory)
    for tool in result:
        if tool["type"] == "namespace":
            tool["tools"] = echo(tool["tools"], defaults)
        elif defaults:
            tool.update(allowed_callers=["direct"], defer_loading=False, **{"async": False})
            if tool["type"] == "function":
                tool["output_schema"] = None
    return result


def stream(echoed):
    seq = lifecycle(ALL_ZERO)
    for event in seq:
        if "response" in event:
            event["response"]["tools"] = copy.deepcopy(echoed)
    return seq
