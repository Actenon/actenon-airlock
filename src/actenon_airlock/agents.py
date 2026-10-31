"""Supported third-party agents: exact, public-option launch profiles.

Each agent runs unchanged from its own image through its documented configuration, and
its entry says how far it has been validated. Anything else needs a reviewed integration;
`airlock run --protected -- ...` still applies the same boundary to any command, without
a compatibility claim.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from pathlib import Path

from .agent_inference import CONTRACT, PRICES
from .common import AirlockError

DECLARATION = "airlock_agent.py"
HEADER = '"""Reviewed declaration of agent authority. Never executed."""'
SUPPORTED = {
    "aider": {
        "image": "actenon-airlock-aider:v2",
        "version": "aider-chat 0.86.2",
    },
    "claude-code": {
        "image": "actenon-airlock-claude-code:v1",
        "version": "@anthropic-ai/claude-code 2.1.308",
        "status": "integration candidate: no scored live acceptance result yet",
        "contract": CONTRACT,
        "max_output_tokens": 16000,
        "max_input_bytes": 2 * 1024 * 1024,
        # Sent by this pinned version. Unlisted features are refused, not forwarded.
        "anthropic_betas": (
            "claude-code-20250219",
            "effort-2025-11-24",
            "interleaved-thinking-2025-05-14",
        ),
    },
}
CLAUDE_TOOLS = "Bash,Read,Edit,Write,Glob,Grep"
CLAUDE_MAX_TURNS = 40


def require_supported(agent: str) -> dict:
    if agent not in SUPPORTED:
        raise AirlockError(
            f"Unsupported agent {agent!r}. Supported agents: {', '.join(sorted(SUPPORTED))}"
        )
    return SUPPORTED[agent]


def declaration(model: str, endpoint: str, github_urls: tuple[str, ...] = ()) -> str:
    """Reviewable source stating the powers an agent installed in an image needs.

    Scan derives authority from source and a profile cannot invent a power, so this
    file is what a reviewer approves. It is never executed.
    """
    if endpoint.endswith("/v1/messages"):
        lines = [
            HEADER,
            "",
            "import anthropic",
            "import requests",
            "",
            f'client = anthropic.Anthropic(base_url="{endpoint.removesuffix("/v1/messages")}", '
            'api_key="none")',
            f'client.messages.create(model="{model}", max_tokens=1, messages=[])',
        ]
        lines += [f'requests.put("{url}")' for url in github_urls]
        return "\n".join(lines) + "\n"
    base = endpoint.removesuffix("/chat/completions")
    if base == endpoint:
        raise AirlockError("Model endpoint must end in /chat/completions or /v1/messages")
    lines = [
        HEADER,
        "",
        "import requests",
        "from openai import OpenAI",
        "",
        f'client = OpenAI(base_url="{base}", api_key="none")',
        f'client.chat.completions.create(model="{model}", messages=[])',
    ]
    lines += [f'requests.put("{url}")' for url in github_urls]
    return "\n".join(lines) + "\n"


# The protected snapshot excludes .git, and a repository map needs one. The agent gets
# a private history of the same files, created inside its own boundary.
_PRIVATE_HISTORY = (
    "git init -q && git add -A && "
    "git -c user.name=agent -c user.email=agent@example.invalid "
    'commit -q --allow-empty -m start && exec "$@"'
)


# The prompt is the message file, and stdin keeps a hostile file name out of the arguments.
_CLAUDE_START = (
    "message=$1; shift; git init -q && git add -A && "
    "git -c user.name=agent -c user.email=agent@example.invalid "
    'commit -q --allow-empty -m start && exec "$@" < "$message"'
)


def write_declaration(root: Path, text: str) -> None:
    """Replace only a declaration this module wrote, never a project's own file."""
    path = root / DECLARATION
    if path.is_symlink() or (
        path.exists() and not path.read_text(errors="replace").startswith(HEADER)
    ):
        raise AirlockError(f"{DECLARATION} already exists and is not an Airlock declaration")
    path.write_text(text)


def usd_to_micro(text: str) -> int:
    try:
        value = Decimal(str(text)) * 1_000_000
    except InvalidOperation as exc:
        raise AirlockError("Prices and spend bounds must be decimal USD amounts") from exc
    if not value.is_finite() or value != value.to_integral_value() or value < 0:
        raise AirlockError("Prices and spend bounds resolve to whole micro-USD")
    return int(value)


def parse_prices(text: str) -> dict:
    """INPUT,CACHE_WRITE,CACHE_READ,OUTPUT in USD per million tokens."""
    values = text.split(",")
    if len(values) != len(PRICES):
        raise AirlockError("Prices need four values: input,cache_write,cache_read,output")
    return {name: usd_to_micro(value) for name, value in zip(PRICES, values)}


def claude_code_command(
    model: str, message_file: str, max_output_tokens: int, budget_usd: str
) -> list[str]:
    """Documented headless mode. Every value here is public configuration, not a secret.

    Pinning all model aliases stops a background call from asking for an unapproved model.
    --max-budget-usd is the agent's own estimate, so it only lets a run end politely; the
    supervisor's spend bound is what holds.
    """
    environment = {
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
        "CLAUDE_CODE_SUBAGENT_MODEL": model,
        "CLAUDE_CODE_MAX_OUTPUT_TOKENS": str(max_output_tokens),
        "CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_UPDATES": "1",
        "DISABLE_FEEDBACK_COMMAND": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": "*",
    }
    return [
        "env", *(f"{name}={value}" for name, value in environment.items()),
        "sh", "-c", _CLAUDE_START, "sh", message_file,
        "claude", "-p", "--model", model, "--output-format", "stream-json", "--verbose",
        "--max-turns", str(CLAUDE_MAX_TURNS), "--max-budget-usd", budget_usd,
        "--permission-mode", "bypassPermissions", "--tools", CLAUDE_TOOLS,
        "--strict-mcp-config",
    ]  # fmt: skip


def command(agent: str, model: str, message_file: str, test_command: str, **options) -> list[str]:
    require_supported(agent)
    if agent == "claude-code":
        return claude_code_command(model, message_file, **options)
    return [
        "env", "LITELLM_LOCAL_MODEL_COST_MAP=True", "GIT_CONFIG_COUNT=1",
        "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=*",
        "sh", "-c", _PRIVATE_HISTORY, "sh",
        "aider", "--model", f"openai/{model}", "--no-stream", "--yes-always",
        "--no-check-update", "--analytics-disable", "--no-show-model-warnings",
        "--no-pretty", "--no-fancy-input", "--edit-format", "diff",
        "--auto-test", "--test-cmd", test_command, "--no-auto-lint",
        "--no-suggest-shell-commands", "--no-detect-urls", "--no-gitignore",
        "--timeout", "500", "--message-file", message_file,
    ]  # fmt: skip
