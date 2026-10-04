"""Python launcher: adapters forward intercepted effects to the parent; unknown effects refuse."""

from __future__ import annotations

import base64
import functools
import importlib
import inspect
import io
import json
import os
import pathlib
import platform
import runpy
import socket
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

import httpx
import requests
from actenon_scan.authority import sdk

from .wire import receive, send

WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
UNSUPPORTED = {
    "socket.connect",
    "socket.connect_ex",
    "socket.bind",
    "socket.getaddrinfo",
    "os.fork",
    "os.forkpty",
    "ctypes.dlopen",
    "ctypes.dlsym",
}
# audit event -> (path argument, dir_fd argument or None, consumed source argument or None)
FS_EVENTS = {
    "os.remove": (0, 1, None),
    "os.rmdir": (0, 1, None),
    "os.mkdir": (0, 2, None),
    "os.rename": (1, 3, 0),
    "os.link": (1, 3, None),
    "os.symlink": (1, 2, None),
    "os.chmod": (0, 2, None),
    "os.chown": (0, 3, None),
    "os.utime": (0, 3, None),
    "os.truncate": (0, None, None),
    "os.setxattr": (0, None, None),
    "os.removexattr": (0, None, None),
}
MKDIR = {"os.mkdir", "pathlib.Path.mkdir"}
RMDIR = {"os.rmdir", "pathlib.Path.rmdir"}
DELETES = {*sdk.FILE_DELETE_FUNCS, *(f"pathlib.Path.{m}" for m in sdk.PATH_DELETE_METHODS)}
CONSUMES_SOURCE = {"shutil.move"}


class RuntimeDenied(PermissionError):
    pass


# A denied request surfaces as the client library's own connection failure, so the
# agent's existing transport error handling treats it as one failed call.
class RequestsDenied(RuntimeDenied, requests.exceptions.ConnectionError):
    def __init__(self, message, *, request):
        requests.exceptions.ConnectionError.__init__(self, message, request=request)


class HttpxDenied(RuntimeDenied, httpx.ConnectError):
    def __init__(self, message, *, request):
        httpx.ConnectError.__init__(self, message, request=request)


class UrllibDenied(RuntimeDenied, urllib.error.URLError):
    def __init__(self, message):
        urllib.error.URLError.__init__(self, message)


def install(sock, root: Path):
    lock = threading.Lock()
    local = threading.local()
    package = Path(__file__).parent.resolve()
    roots = [Path(p).resolve() for p in sys.path if p]
    sdk_config = Path(os.environ["AIRLOCK_EMPTY_SDK_CONFIG"]).resolve()
    metadata_files = {
        Path(p).resolve()
        for p in (
            "/System/Library/CoreServices/SystemVersion.plist",
            "/etc/os-release",
            "/usr/lib/os-release",
            "/etc/mime.types",
        )
    }

    def rpc(value):
        with lock:
            send(sock, value)
            result = receive(sock)
        if not result.get("ok"):
            raise RuntimeDenied("AIRLOCK BLOCKED: " + result.get("reason", "broker refused"))
        return result["response"]

    def locations():
        found = []
        for frame in inspect.stack(context=0):
            path = Path(frame.filename).resolve()
            if path.is_relative_to(root) and not path.is_relative_to(package):
                positions = frame.positions
                found.append(
                    {
                        "file": str(path.relative_to(root)),
                        "line": positions.lineno if positions is not None else frame.lineno,
                        # Scan uses one-based columns; Python bytecode uses zero-based columns.
                        "col": positions.col_offset + 1
                        if positions is not None and positions.col_offset is not None
                        else -1,
                        "end_line": positions.end_lineno if positions is not None else frame.lineno,
                        "end_col": positions.end_col_offset + 1
                        if positions is not None and positions.end_col_offset is not None
                        else -1,
                    }
                )
        return found

    def request(method, url, headers, body):
        if not isinstance(body, (str, bytes, type(None))):
            raise RuntimeDenied("AIRLOCK BLOCKED: streaming request bodies are unsupported")
        if isinstance(body, str):
            body = body.encode()
        response = rpc(
            {
                "kind": "http",
                "method": method,
                "url": str(url),
                "headers": dict(headers),
                "body": base64.b64encode(body or b"").decode(),
                "locations": locations(),
            }
        )
        return response, base64.b64decode(response["body"], validate=True)

    def requests_send(self, prepared, **kwargs):
        try:
            if kwargs.get("verify") is False or kwargs.get("cert") or kwargs.get("proxies"):
                raise RuntimeDenied("AIRLOCK BLOCKED: TLS or proxy overrides are unsupported")
            value, content = request(prepared.method, prepared.url, prepared.headers, prepared.body)
        except RuntimeDenied as exc:
            raise RequestsDenied(str(exc), request=prepared) from None
        response = requests.Response()
        response.status_code = value["status"]
        response.headers.update(value["headers"])
        response.url = value["url"]
        response.request = prepared
        response._content = content
        response.raw = io.BytesIO(content)
        response.encoding = requests.utils.get_encoding_from_headers(response.headers)
        return response

    def httpx_send(self, req, **kwargs):
        try:
            value, content = request(req.method, req.url, req.headers, req.read())
        except RuntimeDenied as exc:
            raise HttpxDenied(str(exc), request=req) from None
        return httpx.Response(
            value["status"], headers=value["headers"], content=content, request=req
        )

    async def async_httpx_send(self, req, **kwargs):
        body = await req.aread()
        try:
            value, content = request(req.method, req.url, req.headers, body)
        except RuntimeDenied as exc:
            raise HttpxDenied(str(exc), request=req) from None
        return httpx.Response(
            value["status"], headers=value["headers"], content=content, request=req
        )

    def urlopen(self, req, data=None, timeout=30, **kwargs):
        if not isinstance(req, urllib.request.Request):
            req = urllib.request.Request(req, data=data)
        try:
            value, content = request(req.get_method(), req.full_url, req.header_items(), req.data)
        except RuntimeDenied as exc:
            raise UrllibDenied(str(exc)) from None
        from email.message import Message
        from urllib.response import addinfourl

        headers = Message()
        for key, val in value["headers"].items():
            headers[key] = val
        response = addinfourl(io.BytesIO(content), headers, value["url"], value["status"])
        response.msg = "Airlock broker response"
        return response

    # requests covers PyGithub; httpx covers current OpenAI/Anthropic transports.
    requests.sessions.Session.send = requests_send
    httpx.Client.send = httpx_send
    httpx.AsyncClient.send = async_httpx_send
    urllib.request.OpenerDirector.open = urlopen

    def refuse(event, target="<local>"):
        try:
            rpc({"kind": "audit-deny", "action": event, "target": target})
        except RuntimeDenied:
            pass
        raise RuntimeDenied("AIRLOCK BLOCKED: unsupported effect " + event)

    def effect(kind, **payload):
        # Our own broker traffic must not re-enter the effect hooks.
        local.busy = True
        try:
            rpc({**payload, "kind": kind, "locations": locations()})
        finally:
            local.busy = False

    def lexical(path) -> str:
        return os.path.normpath(os.path.join(os.getcwd(), os.fsdecode(path)))

    def in_scope(operation, absolute, dir_fd) -> bool:
        # A Scan-named call that was authorized as one effect covers the
        # low-level operations it performs inside its own path.
        for base, mode in getattr(local, "scopes", ()):
            if mode == "tree" and (
                dir_fd or absolute == base or absolute.startswith(base.rstrip(os.sep) + os.sep)
            ):
                return True
            if (
                not dir_fd
                and (
                    (mode == "mkdir-ancestors" and operation in MKDIR)
                    or (mode == "rmdir-ancestors" and operation in RMDIR)
                )
                and base.startswith(absolute.rstrip(os.sep) + os.sep)
            ):
                return True
        return False

    def filesystem(operation, path, src=None, dir_fd=False):
        absolute = None if dir_fd else lexical(path)
        if in_scope(operation, absolute, dir_fd):
            return
        effect(
            "filesystem",
            operation=operation,
            path=os.fsdecode(path),
            src=None if src is None else os.fsdecode(src),
            cwd=os.getcwd(),
            dir_fd=dir_fd,
        )

    def search_path(env):
        if env is None:
            return os.environ.get("PATH", os.defpath)
        for key in ("PATH", b"PATH"):
            if key in env:
                return os.fsdecode(env[key])
        return os.defpath

    def process(operation, executable, argv, cwd, env):
        effect(
            "process",
            operation=operation,
            executable=os.fsdecode(os.fspath(executable)),
            argv=[os.fsdecode(os.fspath(a)) for a in argv],
            cwd=lexical(cwd) if cwd is not None else os.getcwd(),
            search_path=search_path(env),
        )

    def wrap(owner, attr, operation, index, name):
        original = getattr(owner, attr, None)
        if not inspect.isfunction(original):
            return  # C functions are covered by their audit events.

        @functools.wraps(original)
        def wrapper(*args, **kwargs):
            if name is None:
                path = args[0] if args else None
            else:
                path = (
                    kwargs[name] if name in kwargs else (args[index] if len(args) > index else None)
                )
            if path is None or getattr(local, "busy", False):
                return original(*args, **kwargs)
            try:
                path = os.fsdecode(os.fspath(path))
            except TypeError:
                return original(*args, **kwargs)
            src = None
            if operation in CONSUMES_SOURCE:
                src = kwargs.get("src", args[0] if args else None)
                src = os.fsdecode(os.fspath(src)) if src is not None else None
            filesystem(operation, path, src)
            absolute = lexical(path)
            ancestors = "rmdir-ancestors" if operation in DELETES else "mkdir-ancestors"
            added = ((absolute, "tree"), (absolute, ancestors))
            if src is not None:
                added += ((lexical(src), "tree"),)
            previous = getattr(local, "scopes", ())
            local.scopes = previous + added
            try:
                return original(*args, **kwargs)
            finally:
                local.scopes = previous

        setattr(owner, attr, wrapper)

    # Scan's own effect tables decide which library calls are named as one effect.
    for table, keyword in ((sdk.FILE_WRITE_FUNCS, "dst"), (sdk.FILE_DELETE_FUNCS, "path")):
        for canonical_name, index in table.items():
            module_name, _, attr = canonical_name.rpartition(".")
            wrap(importlib.import_module(module_name), attr, canonical_name, index, keyword)
    for method in sorted(sdk.PATH_WRITE_METHODS | sdk.PATH_DELETE_METHODS):
        wrap(pathlib.Path, method, f"pathlib.Path.{method}", 0, None)

    import smtplib

    original_connect = smtplib.SMTP.connect

    def smtp_connect(self, host="localhost", port=0, source_address=None):
        effect("email", host=str(host), port=int(port or 0))
        return original_connect(self, host, port, source_address)

    smtplib.SMTP.connect = smtp_connect

    def audit(event, args):
        if getattr(local, "busy", False):
            return
        if event in UNSUPPORTED:
            # "import ctypes" opens the already-loaded process image; nothing in it is
            # callable without ctypes.dlsym, which stays refused.
            if not (event == "ctypes.dlopen" and args[0] is None):
                refuse(event)
        if event == "subprocess.Popen":
            executable, argv, cwd, env = args
            argv = list(argv)
            executable = argv[0] if executable is None else executable
            process(event, executable, argv, cwd, env)
            local.spawn = os.fsdecode(os.fspath(executable))
            return
        if event == "os.system":
            command = os.fsdecode(args[0])
            process(event, "/bin/sh", ["/bin/sh", "-c", command], None, None)
            return
        if event in {"os.exec", "os.spawn", "os.posix_spawn"}:
            path, argv, env = args[-3:]
            if event == "os.posix_spawn" and getattr(local, "spawn", None) == os.fsdecode(path):
                local.spawn = None  # The Popen that was just authorized.
                return
            process(event, path, list(argv), None, env)
            return
        if event in FS_EVENTS:
            path_i, fd_i, src_i = FS_EVENTS[event]
            path = args[path_i]
            dir_fd = fd_i is not None and args[fd_i] not in (None, -1)
            if isinstance(path, int):
                if event == "os.truncate" or in_scope(event, None, True):
                    return  # A truncatable descriptor was itself opened under authority.
                refuse(event, "<descriptor>")
            filesystem(event, path, None if src_i is None else args[src_i], dir_fd)
            return
        if event == "open":
            path, mode, flags = args
            if isinstance(path, int):
                return
            flags = flags or 0
            target = Path(os.fsdecode(path)).resolve()
            if flags & WRITE_FLAGS:
                if lexical(path) == os.devnull:
                    return
                filesystem("open", path)
                if not flags & os.O_RDWR:
                    return
            if (
                (".airlock" in target.parts and not target.is_relative_to(sdk_config))
                or target.name.startswith(".env")
                or target.suffix in {".pem", ".key", ".p12"}
            ):
                refuse("credential.read")
            if (
                not in_scope("open", lexical(path), False)
                and not target.is_relative_to(root)
                and not any(target.is_relative_to(p) for p in roots)
                and target != Path("/dev/null")
                and target not in metadata_files
            ):
                refuse("filesystem.read.outside-project", str(target))

    sys.addaudithook(audit)
    return rpc


def main():
    fd, root_arg, command_arg = sys.argv[1:]
    root = Path(root_arg).resolve()
    command = json.loads(command_arg)
    sock = socket.socket(fileno=int(fd))
    # Import common trusted adapter dependencies before the restrictive audit hook.
    try:
        import github  # noqa: F401
    except ImportError:
        pass
    sys.dont_write_bytecode = True
    # Standard metadata probing may use subprocesses or temporary files.
    # Complete trusted interpreter setup before installing the agent's effect hooks.
    platform.platform()
    tempfile.gettempdir()
    install(sock, root)
    sys.path.insert(0, str(root))
    try:
        if command[:1] == ["-m"] and len(command) >= 2:
            sys.argv = command[1:]
            runpy.run_module(command[1], run_name="__main__", alter_sys=True)
        elif command:
            path = (root / command[0]).resolve()
            if not path.is_relative_to(root) or path.suffix != ".py":
                raise RuntimeDenied("Only a Python script inside the scanned project is supported")
            sys.argv = [str(path), *command[1:]]
            sys.path.insert(0, str(path.parent))
            runpy.run_path(str(path), run_name="__main__")
        else:
            raise RuntimeDenied("No Python command configured")
    except RuntimeDenied as exc:
        print(str(exc), file=sys.stderr)
        return 3
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
