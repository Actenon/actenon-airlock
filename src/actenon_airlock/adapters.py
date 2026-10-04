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
# These parse a script from argv, so a grant for the binary is a grant to run arbitrary code.
INTERPRETER_NAMES = frozenset({"node", "nodejs", "awk", "gawk", "nawk", "mawk"})
INTERPRETER_STEMS = ("python", "pypy", "perl", "ruby", "php")
# Git config and ssh options that exec a local command. A plain `git status` or `ssh host` does not.
GIT_SHELL_MARKERS = ("sshcommand", "fsmonitor", "corepager")
SSH_SHELL_MARKERS = (
    "proxycommand",
    "localcommand",
    "remotecommand",
    "knownhostscommand",
    "permitlocalcommand",
)

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
        if ev.action == "http.request":
            return "", "Unresolved HTTP method remains blocked"
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


def _interpreter(name: str) -> bool:
    base = os.path.basename(name)
    if base in INTERPRETER_NAMES:
        return True
    for stem in INTERPRETER_STEMS:
        if base == stem:
            return True
        rest = base[len(stem) :] if base.startswith(stem) else ""
        if rest[:1].isdigit() and rest.replace(".", "").isdigit():
            return True
    return False


def _assignment(word: str) -> bool:
    name, sep, _value = word.partition("=")
    return bool(sep and name) and not name.startswith("-") and "/" not in name


@dataclass(frozen=True)
class _Parsed:
    index: int
    direct: bool = False
    pid: bool = False


def _operands(
    argv: list[str],
    index: int,
    *,
    flags: frozenset[str] = frozenset(),
    valued: frozenset[str] = frozenset(),
    attached: tuple[str, ...] = (),
    script: frozenset[str] = frozenset(),
    script_prefixes: tuple[str, ...] = (),
    cluster_flags: str = "",
    cluster_valued: str = "",
    cluster_optional: str = "",
    script_chars: str = "",
    direct: frozenset[str] = frozenset(),
    direct_chars: str = "",
    pid: frozenset[str] = frozenset(),
    pid_chars: str = "",
) -> _Parsed | None:
    """Index of the first operand, or None when an option runs a script or is unknown."""
    saw_direct = False
    saw_pid = False
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            return _Parsed(index + 1, saw_direct, saw_pid)
        if arg in script or any(arg.startswith(prefix) for prefix in script_prefixes):
            return None
        if arg in direct or any(arg.startswith(item) for item in direct if item.endswith("=")):
            saw_direct = True
        if arg in pid or any(arg.startswith(item) for item in pid if item.endswith("=")):
            saw_pid = True
        if arg in flags or arg in direct or arg in pid:
            index += 1
            continue
        if arg in valued:
            if index + 1 >= len(argv):
                return None
            index += 2
            continue
        if any(arg.startswith(prefix) for prefix in attached):
            index += 1
            continue
        if arg.startswith("--"):
            return None
        if arg.startswith("-") and len(arg) > 1:
            body = arg[1:]
            pos = 0
            while pos < len(body):
                char = body[pos]
                if char in script_chars:
                    return None
                if char in direct_chars:
                    saw_direct = True
                if char in pid_chars:
                    saw_pid = True
                if char in cluster_flags or char in direct_chars or char in pid_chars:
                    pos += 1
                    continue
                if char in cluster_optional:
                    if pos + 1 < len(body):
                        index += 1
                        break
                    pos += 1
                    continue
                if char in cluster_valued:
                    if pos + 1 < len(body):
                        index += 1
                    elif index + 1 >= len(argv):
                        return None
                    else:
                        index += 2
                    break
                return None
            else:
                index += 1
            continue
        return _Parsed(index, saw_direct, saw_pid)
    return _Parsed(index, saw_direct, saw_pid)


@dataclass(frozen=True)
class _Wrap:
    """How a wrapper names the single program it execs.

    `empty` is `self` when no command prints a status, `echo` for xargs, or `shell` when the
    wrapper would start a shell. `skip` drops positional operands (a duration, lock file, or
    priority) that are not the command. `direct` options are required before a command is plain
    (`watch` uses `sh -c` unless `--exec`). `pid` options act on an existing process.
    """

    flags: frozenset[str] = frozenset()
    valued: frozenset[str] = frozenset()
    attached: tuple[str, ...] = ()
    script: frozenset[str] = frozenset()
    script_prefixes: tuple[str, ...] = ()
    cluster_flags: str = ""
    cluster_valued: str = ""
    cluster_optional: str = ""
    script_chars: str = ""
    skip: int = 0
    empty: str = "self"
    direct: frozenset[str] = frozenset()
    direct_chars: str = ""
    pid: frozenset[str] = frozenset()
    pid_chars: str = ""


def _unwrap(argv: list[str], spec: _Wrap) -> list[str] | None:
    parsed = _operands(
        argv,
        1,
        flags=spec.flags,
        valued=spec.valued,
        attached=spec.attached,
        script=spec.script,
        script_prefixes=spec.script_prefixes,
        cluster_flags=spec.cluster_flags,
        cluster_valued=spec.cluster_valued,
        cluster_optional=spec.cluster_optional,
        script_chars=spec.script_chars,
        direct=spec.direct,
        direct_chars=spec.direct_chars,
        pid=spec.pid,
        pid_chars=spec.pid_chars,
    )
    if parsed is None:
        return None
    if spec.direct and not parsed.direct:
        return None
    if parsed.pid:
        return []
    index = parsed.index + spec.skip
    if parsed.index + spec.skip > len(argv):
        return None
    if spec.skip and len(argv) - parsed.index <= spec.skip:
        return [] if spec.empty == "self" else None
    rest = argv[index:]
    if rest:
        return rest
    if spec.empty == "shell":
        return None
    if spec.empty == "echo":
        return ["echo"]
    return []


def _unwrap_env(argv: list[str]) -> list[str] | None:
    parsed = _operands(
        argv,
        1,
        flags=frozenset(
            {
                "--ignore-environment",
                "--null",
                "--debug",
                "--list-signal-handling",
                "--help",
                "--version",
                "--block-signal",
                "--default-signal",
                "--ignore-signal",
            }
        ),
        valued=frozenset({"-u", "-C", "--unset", "--chdir"}),
        attached=(
            "--unset=",
            "--chdir=",
            "--block-signal=",
            "--default-signal=",
            "--ignore-signal=",
        ),
        script=frozenset({"-S", "--split-string"}),
        script_prefixes=("--split-string",),
        cluster_flags="i0v",
        cluster_valued="uC",
        script_chars="S",
    )
    if parsed is None:
        return None
    index = parsed.index
    if index < len(argv) and argv[index] == "-":
        index += 1
    while index < len(argv) and _assignment(argv[index]):
        index += 1
    return argv[index:]


def _unwrap_nohup(argv: list[str]) -> list[str] | None:
    if len(argv) == 1:
        return None
    if argv[1] in {"--help", "--version"}:
        return []
    if argv[1] == "--":
        return argv[2:] or None
    if argv[1].startswith("-"):
        return None
    return argv[1:]


def _unwrap_xargs(argv: list[str]) -> list[str] | None:
    flags = frozenset(
        {
            "--null",
            "--open-tty",
            "--interactive",
            "--no-run-if-empty",
            "--verbose",
            "--exit",
            "--show-limits",
            "--help",
            "--version",
            "--eof",
            "--replace",
        }
    )
    valued = frozenset(
        {
            "--arg-file",
            "--delimiter",
            "--max-lines",
            "--max-args",
            "--max-procs",
            "--max-chars",
            "--process-slot-var",
            "-a",
            "-E",
            "-I",
            "-L",
            "-n",
            "-P",
            "-s",
            "-d",
        }
    )
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            index += 1
            break
        if arg in flags:
            index += 1
            continue
        if arg in valued:
            if index + 1 >= len(argv):
                return None
            index += 2
            continue
        if arg.startswith("--"):
            name, sep, _value = arg.partition("=")
            if sep and name in valued | {"--eof", "--replace"}:
                index += 1
                continue
            return None
        if arg.startswith("-") and len(arg) > 1:
            body = arg[1:]
            if body[0] in "eil":
                index += 1
                continue
            pos = 0
            while pos < len(body):
                char = body[pos]
                if char in "0oprtx":
                    pos += 1
                    continue
                if char in "aEILnPsd":
                    if pos + 1 == len(body):
                        if index + 1 >= len(argv):
                            return None
                        index += 2
                    else:
                        index += 1
                    break
                return None
            else:
                index += 1
            continue
        break
    return argv[index:] or ["echo"]


def _unwrap_find(argv: list[str]) -> list[str] | None:
    commands = []
    index = 1
    while index < len(argv):
        if argv[index] in {"-exec", "-execdir", "-ok", "-okdir"}:
            index += 1
            start = index
            while index < len(argv) and argv[index] not in {";", "+"}:
                index += 1
            if index >= len(argv) or start == index:
                return None
            commands.append(argv[start:index])
        index += 1
    if not commands:
        return []
    chains = []
    for command in commands:
        chain = _command_chain(command)
        if chain is None:
            return None
        chains.append(tuple(chain))
    if any(chain != chains[0] for chain in chains):
        return None
    return commands[0]


def _git_runs_shell(argv: list[str]) -> bool:
    for index, arg in enumerate(argv):
        lowered = arg.lower()
        compact = lowered.replace("_", "").replace("-", "")
        if any(marker in compact for marker in GIT_SHELL_MARKERS):
            return True
        if "pager." in lowered or lowered.startswith("pager.") or "core.pager" in lowered:
            return True
        if "!" in arg and "alias" in lowered:
            return True
        if arg.startswith("!") and index and "alias" in argv[index - 1].lower():
            return True
    return False


def _ssh_runs_shell(argv: list[str]) -> bool:
    for arg in argv:
        compact = arg.lower().replace("_", "").replace("-", "")
        if any(marker in compact for marker in SSH_SHELL_MARKERS):
            return True
    return False


_HELP = frozenset({"--help", "--version", "-h", "--help", "-V"})
_WRAP = {
    "nice": _Wrap(
        flags=_HELP,
        valued=frozenset({"-n", "--adjustment"}),
        attached=("--adjustment=",),
        cluster_valued="n",
    ),
    "timeout": _Wrap(
        flags=frozenset(
            {"--preserve-status", "--foreground", "-v", "--verbose", "--help", "--version"}
        ),
        valued=frozenset({"-k", "--kill-after", "-s", "--signal"}),
        attached=("--kill-after=", "--signal="),
        cluster_flags="v",
        cluster_valued="ks",
        skip=1,
    ),
    "stdbuf": _Wrap(
        flags=frozenset({"--help", "--version"}),
        valued=frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
        attached=("--input=", "--output=", "--error="),
        cluster_valued="ioe",
        empty="shell",
    ),
    "setsid": _Wrap(
        flags=frozenset(
            {"-c", "--ctty", "-f", "--fork", "-w", "--wait", "-h", "--help", "-V", "--version"}
        ),
        cluster_flags="cfwhV",
        empty="shell",
    ),
    "flock": _Wrap(
        flags=frozenset(
            {
                "-s",
                "--shared",
                "-x",
                "--exclusive",
                "-u",
                "--unlock",
                "-n",
                "--nonblock",
                "-o",
                "--close",
                "-F",
                "--no-fork",
                "--verbose",
                "-h",
                "--help",
                "-V",
                "--version",
            }
        ),
        valued=frozenset({"-w", "--timeout", "-E", "--conflict-exit-code"}),
        attached=("--timeout=", "--conflict-exit-code="),
        script=frozenset({"-c", "--command"}),
        script_prefixes=("--command",),
        cluster_flags="sxunoFhV",
        cluster_valued="wE",
        script_chars="c",
        skip=1,
    ),
    "ionice": _Wrap(
        flags=frozenset({"-t", "--ignore", "-h", "--help", "-V", "--version"}),
        valued=frozenset(
            {"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"}
        ),
        attached=("--class=", "--classdata=", "--pid=", "--pgid=", "--uid="),
        cluster_flags="thV",
        cluster_valued="cnpuP",
        pid=frozenset(
            {"-p", "-P", "-u", "--pid", "--pgid", "--uid", "--pid=", "--pgid=", "--uid="}
        ),
        pid_chars="pu",
    ),
    "chrt": _Wrap(
        flags=frozenset(
            {
                "-b",
                "--batch",
                "-d",
                "--deadline",
                "-f",
                "--fifo",
                "-i",
                "--idle",
                "-o",
                "--other",
                "-r",
                "--rr",
                "-R",
                "--reset-on-fork",
                "-a",
                "--all-tasks",
                "-m",
                "--max",
                "-v",
                "--verbose",
                "-h",
                "--help",
                "-V",
                "--version",
            }
        ),
        valued=frozenset(
            {"-T", "--sched-runtime", "-P", "--sched-period", "-D", "--sched-deadline"}
        ),
        attached=("--sched-runtime=", "--sched-period=", "--sched-deadline="),
        cluster_flags="bdfiorRamvhV",
        cluster_valued="TPD",
        skip=1,
        pid=frozenset({"-p", "--pid", "--pid="}),
        pid_chars="p",
    ),
    "taskset": _Wrap(
        flags=frozenset(
            {"-a", "--all-tasks", "-c", "--cpu-list", "-h", "--help", "-V", "--version"}
        ),
        cluster_flags="achV",
        skip=1,
        pid=frozenset({"-p", "--pid", "--pid="}),
        pid_chars="p",
    ),
    "prlimit": _Wrap(
        flags=frozenset({"--noheadings", "--raw", "--verbose", "-h", "--help", "-V", "--version"}),
        valued=frozenset(
            {
                "-p",
                "--pid",
                "-o",
                "--output",
                "-c",
                "--core",
                "-d",
                "--data",
                "-e",
                "--nice",
                "-f",
                "--fsize",
                "-i",
                "--sigpending",
                "-l",
                "--memlock",
                "-m",
                "--rss",
                "-n",
                "--nofile",
                "-q",
                "--msgqueue",
                "-r",
                "--rtprio",
                "-s",
                "--stack",
                "-t",
                "--cpu",
                "-u",
                "--nproc",
                "-v",
                "--as",
                "-x",
                "--locks",
                "-y",
                "--rttime",
            }
        ),
        attached=tuple(
            f"--{name}="
            for name in (
                "pid",
                "output",
                "core",
                "data",
                "nice",
                "fsize",
                "sigpending",
                "memlock",
                "rss",
                "nofile",
                "msgqueue",
                "rtprio",
                "stack",
                "cpu",
                "nproc",
                "as",
                "locks",
                "rttime",
            )
        ),
        cluster_flags="hV",
        cluster_valued="pocdefilmnqrstuvxy",
        pid=frozenset({"-p", "--pid", "--pid="}),
        pid_chars="p",
    ),
    "watch": _Wrap(
        flags=frozenset(
            {
                "-b",
                "--beep",
                "-c",
                "--color",
                "-C",
                "--no-color",
                "-d",
                "--differences",
                "-e",
                "--errexit",
                "-g",
                "--chgexit",
                "-p",
                "--precise",
                "-r",
                "--no-rerun",
                "-t",
                "--no-title",
                "-w",
                "--no-wrap",
                "-h",
                "--help",
                "-v",
                "--version",
            }
        ),
        valued=frozenset({"-n", "--interval", "-q", "--equexit"}),
        attached=("--differences=", "--interval=", "--equexit="),
        cluster_flags="bcCdegprtw",
        cluster_valued="nq",
        cluster_optional="d",
        empty="shell",
        direct=frozenset({"-x", "--exec"}),
        direct_chars="x",
    ),
    "unshare": _Wrap(
        flags=frozenset(
            {
                "-f",
                "--fork",
                "-r",
                "--map-root-user",
                "-c",
                "--map-current-user",
                "--map-auto",
                "--keep-caps",
                "-h",
                "--help",
                "-V",
                "--version",
                "--mount",
                "--uts",
                "--ipc",
                "--net",
                "--pid",
                "--user",
                "--cgroup",
                "--time",
                "--kill-child",
                "--mount-proc",
            }
        ),
        valued=frozenset(
            {
                "--map-user",
                "--map-group",
                "--map-users",
                "--map-groups",
                "--propagation",
                "--setgroups",
                "-R",
                "--root",
                "-w",
                "--wd",
                "-S",
                "--setuid",
                "-G",
                "--setgid",
                "--monotonic",
                "--boottime",
            }
        ),
        attached=(
            "--mount=",
            "--uts=",
            "--ipc=",
            "--net=",
            "--pid=",
            "--user=",
            "--cgroup=",
            "--time=",
            "--kill-child=",
            "--mount-proc=",
            "--map-user=",
            "--map-group=",
            "--map-users=",
            "--map-groups=",
            "--propagation=",
            "--setgroups=",
            "--root=",
            "--wd=",
            "--setuid=",
            "--setgid=",
            "--monotonic=",
            "--boottime=",
        ),
        cluster_flags="frchV",
        cluster_valued="SRGw",
        cluster_optional="muinpUCT",
        empty="shell",
    ),
    "nsenter": _Wrap(
        flags=frozenset(
            {
                "-a",
                "--all",
                "--preserve-credentials",
                "-F",
                "--no-fork",
                "-Z",
                "--follow-context",
                "-e",
                "--env",
                "-h",
                "--help",
                "-V",
                "--version",
                "--mount",
                "--uts",
                "--ipc",
                "--net",
                "--pid",
                "--user",
                "--cgroup",
                "--time",
                "--setuid",
                "--setgid",
                "--root",
                "--wd",
            }
        ),
        valued=frozenset({"-t", "--target", "-W", "--wdns"}),
        attached=(
            "--target=",
            "--mount=",
            "--uts=",
            "--ipc=",
            "--net=",
            "--pid=",
            "--user=",
            "--cgroup=",
            "--time=",
            "--setuid=",
            "--setgid=",
            "--root=",
            "--wd=",
            "--wdns=",
        ),
        cluster_flags="aFZehV",
        cluster_valued="tW",
        cluster_optional="muinpCUTSGrw",
        empty="shell",
    ),
}


def _wrapper_command(program: str, argv: list[str]) -> list[str] | None:
    if program == "env":
        return _unwrap_env(argv)
    if program == "nohup":
        return _unwrap_nohup(argv)
    if program == "xargs":
        return _unwrap_xargs(argv)
    if program == "find":
        return _unwrap_find(argv)
    spec = _WRAP.get(program)
    if spec is None:
        return None
    return _unwrap(argv, spec)


def _command_chain(argv: list[str]) -> list[str] | None:
    """Plain program names this argv will exec, inner first. None when it parses a script."""
    if not argv or not argv[0]:
        return None
    program = os.path.basename(argv[0])
    if program in {".", ".."} or program in SHELL_BUILTINS or program in SHELLS:
        return None
    if _interpreter(program):
        return None
    if program == "git":
        return None if _git_runs_shell(argv) else ["git"]
    if program == "ssh":
        return None if _ssh_runs_shell(argv) else ["ssh"]
    if program in _WRAP or program in {"env", "nohup", "xargs", "find"}:
        inner = _wrapper_command(program, argv)
        if inner is None:
            return None
        if not inner:
            return [program]
        chain = _command_chain(inner)
        if chain is None:
            return None
        return list(dict.fromkeys([*chain, program]))
    return [program]


def _direct_program(words: list[str]) -> bool:
    """True when a shell -c string execs one plain program, not a script or another shell."""
    if words[0] in SHELL_BUILTINS or os.path.basename(words[0]) in SHELLS:
        return False
    if any(os.path.basename(word) in SHELLS for word in words):
        return False
    return _command_chain(words) is not None


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
            f"Run '{p['resource']}' from the broker PATH as one plain program "
            "that does not parse a script; the program itself runs outside Airlock"
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
            chain = _command_chain(words) if words is not None and _direct_program(words) else None
            candidates = []
            if chain:
                try:
                    resolved_programs = [
                        _program(name, cwd, search_path, context) for name in chain
                    ]
                    candidates.extend(
                        power("process.exec", program, PROCESS_TRANSPORT)
                        for program, _resolved in resolved_programs
                    )
                    detail.update(
                        program=resolved_programs[0][0], executable=resolved_programs[0][1]
                    )
                except AirlockError:
                    candidates = []
            if candidates:
                candidates.append(power("process.exec", shell, PROCESS_TRANSPORT))
                detail.setdefault("program", shell)
                detail.setdefault("executable", resolved_shell)
                detail["shell"] = True
                return Effect(tuple(candidates), detail["executable"], dict(detail), detail)
            # A shell grant must not execute operators, a script file, stdin, startup files,
            # an interpreter, a wrapper around a script, or another shell.
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
        chain = _command_chain(argv)

        def script():
            return Effect(
                (power("process.exec", SHELL_SYNTAX_RESOURCE, PROCESS_TRANSPORT),),
                resolved,
                dict(detail),
                detail,
            )

        # An interpreter, or a wrapper/git/ssh invocation that parses a script, is not a plain
        # program. A wrapper around one plain program names that program and the wrapper.
        if not chain or chain[-1] != program:
            return script()
        try:
            resolved_programs = [_program(name, cwd, search_path, context) for name in chain]
        except AirlockError:
            return script()
        detail.update(program=resolved_programs[0][0], executable=resolved_programs[0][1])
        return Effect(
            tuple(
                power("process.exec", name, PROCESS_TRANSPORT) for name, _path in resolved_programs
            ),
            detail["executable"],
            dict(detail),
            detail,
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
