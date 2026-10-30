"""Supported third-party agents: exact, public-option launch profiles.

Only agents validated by the versioned acceptance programme are listed. Each runs
unchanged from its own image through its standard OpenAI-compatible configuration.
Anything else needs a reviewed integration; `airlock run --protected -- ...` still
applies the same boundary to any command, without a compatibility claim.
"""

from __future__ import annotations

from pathlib import Path

from .common import AirlockError

DECLARATION = "airlock_agent.py"
HEADER = '"""Reviewed declaration of agent authority. Never executed."""'
SUPPORTED = {
    "aider": {
        "image": "actenon-airlock-aider:v2",
        "version": "aider-chat 0.86.2",
    }
}


def require_supported(agent: str) -> dict:
    if agent not in SUPPORTED:
        raise AirlockError(
            f"Unsupported agent {agent!r}. Validated agents: {', '.join(sorted(SUPPORTED))}"
        )
    return SUPPORTED[agent]


def declaration(model: str, endpoint: str, github_urls: tuple[str, ...] = ()) -> str:
    """Reviewable source stating the powers an agent installed in an image needs.

    Scan derives authority from source and a profile cannot invent a power, so this
    file is what a reviewer approves. It is never executed.
    """
    base = endpoint.removesuffix("/chat/completions")
    if base == endpoint:
        raise AirlockError("Model endpoint must end in /chat/completions")
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


def write_declaration(root: Path, text: str) -> None:
    """Replace only a declaration this module wrote, never a project's own file."""
    path = root / DECLARATION
    if path.is_symlink() or (
        path.exists() and not path.read_text(errors="replace").startswith(HEADER)
    ):
        raise AirlockError(f"{DECLARATION} already exists and is not an Airlock declaration")
    path.write_text(text)


def command(agent: str, model: str, message_file: str, test_command: str) -> list[str]:
    require_supported(agent)
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
