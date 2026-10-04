"""Adapters by power kind: Scan's vocabulary in, exact runtime candidates out.

Every power Scan names has a kind (the action prefix: http, github, process, filesystem, email).
An adapter for a kind does two translations and nothing else:

- static: bind resolved Scan evidence to an approvable power (action, resource, transport);
- runtime: name an intercepted effect in the same vocabulary, as candidate powers.

The broker binds candidates to a scanned project callsite, and Permit decides. Adapters never
decide. A kind with no adapter cannot be intercepted, so it refuses launch; an adapter without an
executor intercepts its calls so that Permit denies them.
"""

from __future__ import annotations

import os
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path

from actenon_scan.authority import ResourceState, classify_http, normalise_path, sdk

from .common import AirlockError, digest, origin, power, validate_url

PROCESS_TRANSPORT = "local-process"
FILESYSTEM_TRANSPORT = "local-filesystem"
SHELL_SYNTAX = frozenset("|&;<>()$`\\*?[]#~{}!\n\r")
SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "rbash", "mksh", "fish"})
# Not a Scan program name, so a grant for the shell itself cannot satisfy it.
SHELL_SYNTAX_RESOURCE = "<shell-syntax>"
# Builtins that read or replace the shell command, so a "plain" word list is still a script.
SHELL_BUILTINS = frozenset({".", "source", "eval", "exec", "command", "builtin"})
SHELL_STARTUP_ENV = frozenset({"BASH_ENV", "ENV", "ZDOTDIR"})
HARMLESS_LONG_OPTIONS = frozenset({"--noprofile", "--norc", "--posix"})

FS_WRITE = frozenset(
    {
        *sdk.FILE_WRITE_FUNCS,
        *(f"pathlib.Path.{m}" for m in sdk.PATH_WRITE_METHODS),
        "open",
        "os.mkdir",
        "os.rename",
        "os.link",
        "os.symlink",
        "os.chmod",
        "os.chown",
        "os.utime",
        "os.truncate",
        "os.setxattr",
        "os.removexattr",
    }
)
FS_DELETE = frozenset(
    {
        *sdk.FILE_DELETE_FUNCS,
        *(f"pathlib.Path.{m}" for m in sdk.PATH_DELETE_METHODS),
        "os.remove",
        "os.rmdir",
    }
)
PROCESS_OPERATIONS = frozenset(
    {"subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn"}
)


@dataclass(frozen=True)
class Effect:
    """One intercepted runtime effect, named in Scan's vocabulary."""

    candidates: tuple[dict, ...]
    target: str
    params: dict
    detail: dict


@dataclass(frozen=True)
class Context:
    root: Path
    home: Path
    search_path: str


class Adapter:
    kinds: tuple[str, ...] = ()
    channel = ""
    # "broker": the parent performs the effect inside the Kernel callback.
    # "agent": the Kernel callback releases the effect to the cooperative child.
    # None: intercepted and denied; nothing can be approved for this kind.
    executor: str | None = None
    default_action = "unsupported"

    def bind(self, ev) -> tuple[str, str | None]:
        raise NotImplementedError

    def scope(self, p: dict) -> str:
        raise NotImplementedError

    def classify(self, message: dict, context: Context) -> Effect:
        raise NotImplementedError


def http_candidates(method: str, url: str) -> tuple[dict, ...]:
    url = validate_url(url)
    out = []
    # A method-agnostic Scan entry (http.request) names the same exact URL for any method.
    for http in (classify_http(method, url), classify_http("", url)):
        if not http.resource or http.state is not ResourceState.RESOLVED:
            raise AirlockError("Runtime authority could not be resolved")
        transport = origin(url) if http.action.startswith("github.") else url
        candidate = power(http.action, http.resource, transport)
        if candidate not in out:
            out.append(candidate)
    return tuple(out)


class HttpAdapter(Adapter):
    kinds = ("http", "github")
    channel = "http"
    executor = "broker"
    default_action = "http.request"

    def bind(self, ev):
        if ev.url:
            try:
                url = validate_url(ev.url)
            except AirlockError:
                return "", "Unsafe or unsupported HTTP URL"
            actual = classify_http(ev.method, url)
            if actual.action != ev.action or actual.resource != ev.resource:
                return "", "Scan evidence and transport disagree"
            return (origin(url) if ev.action.startswith("github.") else url), None
        if ev.action.startswith("github."):
            return "https://api.github.com", None
        return "", "No exact transport URL in structured evidence"

    def scope(self, p):
        action, resource = p["action"], p["resource"]
        if action == "http.request":
            return f"Any HTTP method to exactly {p['transport']}"
        if action.startswith("http."):
            return f"{action[5:].upper()} to exactly {p['transport']}"
        if action == "github.graphql":
            return "Any GitHub GraphQL query or mutation the bound credential permits"
        where = "the authenticated account" if resource == "github.com" else resource
        return f"GitHub {action[7:]} on {where} through {p['transport']}"

    def classify(self, message, context):
        method = message["method"].upper()
        url = validate_url(message["url"])
        return Effect(http_candidates(method, url), url, {"method": method}, {"method": method})


def _program(name: str, cwd: str, search_path: str, context: Context) -> tuple[str, str]:
    program = os.path.basename(name)
    if not program or program in {".", ".."}:
        raise AirlockError("Empty program name")
    expected = shutil.which(program, path=context.search_path)
    if expected is None:
        raise AirlockError(f"Program '{program}' is not on the broker PATH")
    expected = os.path.realpath(expected)
    if "/" in name:
        actual = os.path.realpath(os.path.join(cwd, name))
    else:
        found = shutil.which(name, path=search_path)
        actual = os.path.realpath(found) if found else ""
    if actual != expected:
        raise AirlockError(f"'{name}' does not resolve to the broker PATH program '{program}'")
    return program, expected


def _plain_command(command: str) -> list[str] | None:
    """Shell text the shell would run as one plain command, or None."""
    if not command.strip() or any(c in SHELL_SYNTAX for c in command):
        return None
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    return words if words and "=" not in words[0] else None


def _startup_env(message: dict) -> list[str]:
    raw = message.get("startup_env") or []
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise AirlockError("Malformed process request")
    return [item for item in raw if item in SHELL_STARTUP_ENV]


def _shell_command_text(argv: list[str]) -> str | None:
    """The operand of a non-interactive `shell -c`, or None when a script can be read elsewhere.

    Stdin (`-s`), a script argument, login/interactive startup, and `--rcfile`/`--init-file`
    execute shell syntax that is not the `-c` string. Those invocations are not a plain command.
    """
    index = 1
    command_at = None
    while index < len(argv):
        flag = argv[index]
        if flag == "--" or flag.startswith("--") and flag not in HARMLESS_LONG_OPTIONS:
            return None
        if flag in HARMLESS_LONG_OPTIONS:
            index += 1
            continue
        if flag.startswith("-") and flag != "-":
            body = flag[1:]
            if any(char in body for char in "ils"):
                return None
            if "c" in body:
                command_at = index + 1
                break
            index += 1
            continue
        return None
    if command_at is None or command_at >= len(argv):
        return None
    if command_at != len(argv) - 1:
        raise AirlockError("Shell positional parameters are unsupported")
    return argv[command_at]


def _direct_program(words: list[str]) -> bool:
    """True when every word is an ordinary program argument, not another shell or builtin."""
    if words[0] in SHELL_BUILTINS or os.path.basename(words[0]) in SHELLS:
        return False
    return all(os.path.basename(word) not in SHELLS for word in words)


def _follows_symlink(path: str) -> bool:
    """True when any lexical component of `path` is a symbolic link."""
    current = path
    while True:
        if os.path.islink(current):
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


class ProcessAdapter(Adapter):
    kinds = ("process",)
    channel = "process"
    executor = "agent"
    default_action = "process.exec"

    def bind(self, ev):
        if os.path.basename(ev.resource) != ev.resource or ev.resource in {".", ".."}:
            return "", "Process authority must name one program"
        return PROCESS_TRANSPORT, None

    def scope(self, p):
        return (
            f"Run '{p['resource']}' from the broker PATH with any arguments and no shell syntax; "
            "the program itself runs outside Airlock"
        )

    def classify(self, message, context):
        operation = message["operation"]
        executable, argv, cwd = message["executable"], message["argv"], message["cwd"]
        search_path = message.get("search_path") or ""
        if operation not in PROCESS_OPERATIONS:
            raise AirlockError("Unsupported process operation")
        if not (
            isinstance(executable, str)
            and isinstance(argv, list)
            and argv
            and all(isinstance(a, str) for a in argv)
            and isinstance(cwd, str)
            and os.path.isabs(cwd)
            and isinstance(search_path, str)
        ):
            raise AirlockError("Malformed process request")
        if any("\x00" in a for a in [executable, *argv]):
            raise AirlockError("Malformed process request")
        detail = {
            "operation": operation,
            "argc": len(argv),
            "argv_sha256": digest(argv),
            "cwd": cwd,
        }
        if os.path.basename(executable) in SHELLS:
            shell, resolved_shell = _program(executable, cwd, search_path, context)
            if os.path.basename(argv[0]) != shell:
                raise AirlockError("argv[0] does not name the executed program")
            startup = _startup_env(message)
            text = None if startup else _shell_command_text(argv)
            words = _plain_command(text) if text is not None else None
            candidates = []
            if words is not None and _direct_program(words):
                try:
                    program, resolved = _program(words[0], cwd, search_path, context)
                    candidates.append(power("process.exec", program, PROCESS_TRANSPORT))
                    detail.update(program=program, executable=resolved)
                except AirlockError:
                    candidates = []
            if candidates:
                candidates.append(power("process.exec", shell, PROCESS_TRANSPORT))
                detail.setdefault("program", shell)
                detail.setdefault("executable", resolved_shell)
                detail["shell"] = True
                return Effect(tuple(candidates), detail["executable"], dict(detail), detail)
            # A shell grant must not execute operators, a script file, stdin, startup files,
            # or another shell hidden in an otherwise plain command.
            detail.update(program=shell, executable=resolved_shell, shell=True)
            if startup:
                detail["startup_env"] = startup
            return Effect(
                (power("process.exec", SHELL_SYNTAX_RESOURCE, PROCESS_TRANSPORT),),
                resolved_shell,
                dict(detail),
                detail,
            )
        program, resolved = _program(executable, cwd, search_path, context)
        if os.path.basename(argv[0]) != program:
            raise AirlockError("argv[0] does not name the executed program")
        detail.update(program=program, executable=resolved, shell=False)
        return Effect(
            (power("process.exec", program, PROCESS_TRANSPORT),), resolved, dict(detail), detail
        )


def _spellings(absolute: str, cwd: str, home: Path) -> list[str]:
    """Scan resource spellings of one lexical absolute path: cwd-relative, home, absolute."""
    out = []
    for base, prefix in ((cwd, ""), (str(home), "~/")):
        rel = os.path.relpath(absolute, base)
        if rel != "." and not rel.startswith(".."):
            out.append(normalise_path(prefix + rel))
    out.append(normalise_path(absolute))
    return list(dict.fromkeys(s for s in out if s))


class FilesystemAdapter(Adapter):
    kinds = ("filesystem",)
    channel = "filesystem"
    executor = "agent"
    default_action = "filesystem.write"

    def bind(self, ev):
        if ev.resource == "./.airlock" or ev.resource.startswith("./.airlock/"):
            return "", "Airlock state is not writable by the agent"
        return FILESYSTEM_TRANSPORT, None

    def scope(self, p):
        verb = "Delete" if p["action"] == "filesystem.delete" else "Create or modify"
        return f"{verb} exactly {p['resource']} (a Scan-named tree operation includes its contents)"

    def classify(self, message, context):
        operation, path, cwd = message["operation"], message["path"], message["cwd"]
        if operation in {"os.link", "os.symlink"}:
            raise AirlockError("Link creation requires protected filesystem object binding")
        if operation in FS_WRITE:
            action = "filesystem.write"
        elif operation in FS_DELETE:
            action = "filesystem.delete"
        else:
            raise AirlockError("Unsupported filesystem operation")
        if message.get("dir_fd"):
            raise AirlockError("Directory-descriptor-relative paths are unsupported")
        if not (isinstance(path, str) and path and isinstance(cwd, str) and os.path.isabs(cwd)):
            raise AirlockError("Malformed filesystem request")
        if "\x00" in path:
            raise AirlockError("Malformed filesystem request")
        absolute = os.path.normpath(os.path.join(cwd, path))
        detail = {"operation": operation, "path": absolute}
        state = os.path.join(str(context.root), ".airlock")
        paths = [absolute]
        src = message.get("src")
        if src is not None:
            if not isinstance(src, str) or "\x00" in src:
                raise AirlockError("Malformed filesystem request")
            detail["src"] = os.path.normpath(os.path.join(cwd, src))
            source = Path(detail["src"]).resolve()
            if (
                not source.is_relative_to(context.root)
                or (context.root / ".airlock").is_relative_to(source)
                or ".airlock" in source.parts
                or source.name.startswith(".env")
                or source.suffix in {".pem", ".key", ".p12"}
            ):
                raise AirlockError(
                    "Consumed filesystem source is outside the project or private, including Airlock state"
                )
            paths.append(detail["src"])
        if any(p == state or p.startswith(state + os.sep) for p in paths):
            raise AirlockError("Airlock state is not writable by the agent")
        if any(_follows_symlink(p) for p in paths):
            raise AirlockError("Writing through a symbolic link is unsupported")
        candidates = tuple(
            power(action, s, FILESYSTEM_TRANSPORT) for s in _spellings(absolute, cwd, context.home)
        )
        return Effect(candidates, absolute, dict(detail), detail)


class EmailAdapter(Adapter):
    kinds = ("email",)
    channel = "email"
    executor = None
    default_action = "email.send"

    def bind(self, ev):
        return "", "No execution adapter: email.send calls are denied at runtime"

    def scope(self, p):
        return f"Send mail through {p['resource']} (no execution adapter; always denied)"

    def classify(self, message, context):
        host = message.get("host")
        if not isinstance(host, str) or not host or any(c in host for c in "/@\x00 "):
            raise AirlockError("Malformed mail server")
        port = message.get("port") or 0
        target = f"smtp://{host.lower()}:{int(port)}"
        candidate = power("email.send", host.lower(), "smtp")
        return Effect((candidate,), target, {"port": int(port)}, {"host": host.lower()})


REGISTRY: dict[str, Adapter] = {}
for _adapter in (HttpAdapter(), ProcessAdapter(), FilesystemAdapter(), EmailAdapter()):
    for _kind in _adapter.kinds:
        REGISTRY[_kind] = _adapter
CHANNELS = {a.channel: a for a in REGISTRY.values()}


def adapter_for(action: str) -> Adapter | None:
    return REGISTRY.get(action.partition(".")[0])


def scope(p: dict) -> str:
    adapter = adapter_for(p["action"])
    return adapter.scope(p) if adapter else "No Airlock adapter"
