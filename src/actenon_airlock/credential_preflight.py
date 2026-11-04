"""Supervisor-side credential pre-flight. The key never leaves the supervisor.

V4.4's live run failed because a silent prompt consumed the runner command,
which then became the API key. Two independent checks run before anything is
set up, reserved or dispatched:

1. A local format check that refuses empty, missing and obviously malformed
   input (whitespace, control characters, paths, wrong prefix, implausible
   length). It sends nothing.
2. One narrowly scoped provider authentication check: GET of the frozen model's
   metadata. It sends no prompt, starts no inference and should not be billed.
   Success means the provider accepted the credential for that lookup. It is
   NOT proof of model entitlement, quota, spend limits or billing.

Nothing here prints, logs or persists the credential, any fragment of it or any
provider message. Results use fixed strings and integer status codes only.
"""

from __future__ import annotations

import contextlib
import os
import re
import stat
from pathlib import Path

import httpx

from . import provider_errors
from .common import AirlockError

MEANING = (
    "provider accepted the credential for one model-metadata lookup; "
    "not proof of model entitlement, quota, spend limit or billing"
)
MODELS_ENDPOINT = "https://api.openai.com/v1/models/"
MIN_LENGTH = 20
MAX_LENGTH = 512
_BODY = re.compile(r"[A-Za-z0-9_-]+")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class CredentialRefused(AirlockError):
    """Fixed-text refusal; never carries the credential or provider content."""


def format_problems(value) -> list[str]:
    """Fixed reasons why `value` cannot be an OpenAI API key. Empty if plausible."""
    if value is None:
        return ["missing"]
    if not isinstance(value, str):
        return ["invalid-type"]
    if value == "":
        return ["empty"]
    problems = []
    if any(ch.isspace() for ch in value):
        problems.append("whitespace")
    if any((ord(ch) < 32 or ord(ch) == 127) and not ch.isspace() for ch in value):
        problems.append("control-characters")
    if not value.isascii():
        problems.append("non-ascii")
    if len(value) < MIN_LENGTH:
        problems.append("too-short")
    if len(value) > MAX_LENGTH:
        problems.append("too-long")
    if not value.startswith("sk-"):
        problems.append("unexpected-prefix")
    elif not _BODY.fullmatch(value[3:]):
        problems.append("unexpected-characters")
    return problems


def read_credential_file(path: Path) -> str:
    """One line from an owner-only regular file (e.g. written by a secret manager)."""
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        raise CredentialRefused("credential file is missing or unreadable") from None
    if not stat.S_ISREG(info.st_mode):
        raise CredentialRefused("credential file must be a regular file, not a link")
    if info.st_mode & 0o077:
        raise CredentialRefused("credential file is readable by other users; chmod 600 it")
    if info.st_uid != os.geteuid():
        raise CredentialRefused("credential file must be owned by the supervisor user")
    if info.st_size > MAX_LENGTH + 2:
        raise CredentialRefused("credential file is too large to hold one key")
    raw = path.read_bytes()
    text = raw.decode("ascii", errors="replace")
    text = text[:-2] if text.endswith("\r\n") else text[:-1] if text.endswith("\n") else text
    if "\n" in text or "\r" in text:
        raise CredentialRefused("credential file must contain exactly one line")
    return text


def supervisor_credential(environment_value, credential_file=None) -> str:
    """Load and locally validate the credential from exactly one source."""
    if credential_file is not None and environment_value:
        raise CredentialRefused(
            "supply the credential from exactly one source (file or environment)"
        )
    value = (
        read_credential_file(credential_file) if credential_file is not None else environment_value
    )
    problems = format_problems(value)
    if problems:
        size = f"; {len(value)} characters" if isinstance(value, str) else ""
        raise CredentialRefused(
            f"malformed credential input ({', '.join(problems)}{size}); nothing was sent"
        )
    return value


@contextlib.contextmanager
def supervisor_scope(name: str, value: str):
    """Expose a credential in os.environ only while the broker reads it.

    The broker copies bound credentials into its own memory at construction.
    Keeping the variable out of the process environment otherwise means no
    later host subprocess can inherit it, whatever its launch path.
    """
    previous = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


def authenticate(key: str, model: str, *, client: httpx.Client | None = None) -> dict:
    """One promptless, non-inference authentication check against the model lookup."""
    if not _MODEL.fullmatch(model):
        raise CredentialRefused("model identifier is not a plain provider model name")
    owned = client is None
    if owned:
        client = httpx.Client(timeout=15.0, follow_redirects=False, trust_env=False)
    result: dict = {"http_status": None, "outcome": "unreachable", "meaning": MEANING}
    try:
        with client.stream(
            "GET", MODELS_ENDPOINT + model, headers={"Authorization": "Bearer " + key}
        ) as response:
            body = bytearray()
            for part in response.iter_bytes():
                body.extend(part)
                if len(body) > provider_errors.MAX_ERROR_BYTES:
                    break
            status = response.status_code
    except httpx.HTTPError:
        return result  # exception text can carry request details; never copy it
    finally:
        if owned:
            client.close()
    result["http_status"] = status
    result["outcome"] = (
        "authenticated"
        if status == 200
        else "rejected"
        if status in (401, 403)
        else "model-unavailable"
        if status == 404
        else "unavailable"
    )
    if status != 200:
        code = provider_errors.status_diagnostic(status, bytes(body)).get("provider_error_code")
        if code in provider_errors.PROVIDER_ERROR_CODES:
            result["provider_error_code"] = code
    return result
