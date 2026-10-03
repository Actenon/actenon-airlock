"""Python launcher: HTTP adapters forward to the parent; unsupported effects refuse."""

from __future__ import annotations

import base64
import inspect
import io
import json
import os
import platform
import runpy
import socket
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

import httpx
import requests

from .wire import receive, send


class RuntimeDenied(RuntimeError):
    pass


def install(sock, root: Path):
    lock = threading.Lock()
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
        if kwargs.get("verify") is False or kwargs.get("cert") or kwargs.get("proxies"):
            raise RuntimeDenied("AIRLOCK BLOCKED: TLS or proxy overrides are unsupported")
        value, content = request(prepared.method, prepared.url, prepared.headers, prepared.body)
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
        value, content = request(req.method, req.url, req.headers, req.read())
        return httpx.Response(
            value["status"], headers=value["headers"], content=content, request=req
        )

    async def async_httpx_send(self, req, **kwargs):
        body = await req.aread()
        value, content = request(req.method, req.url, req.headers, body)
        return httpx.Response(
            value["status"], headers=value["headers"], content=content, request=req
        )

    def urlopen(self, req, data=None, timeout=30, **kwargs):
        if not isinstance(req, urllib.request.Request):
            req = urllib.request.Request(req, data=data)
        value, content = request(req.get_method(), req.full_url, req.header_items(), req.data)
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

    def audit(event, args):
        if event in {
            "socket.connect",
            "socket.connect_ex",
            "socket.bind",
            "socket.getaddrinfo",
            "subprocess.Popen",
            "os.system",
            "os.posix_spawn",
            "os.fork",
            "os.forkpty",
            "ctypes.dlopen",
            "ctypes.dlsym",
            "os.exec",
            "os.spawn",
        }:
            refuse(event)
        if event in {
            "os.remove",
            "os.rename",
            "os.rmdir",
            "os.mkdir",
            "os.link",
            "os.symlink",
            "os.chmod",
            "os.chown",
            "os.truncate",
            "os.utime",
        }:
            refuse(event)
        if event == "open":
            path, mode, flags = args
            if isinstance(path, int):
                return
            target = Path(os.fsdecode(path)).resolve()
            if (flags or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                refuse("filesystem.write", str(target))
            if (
                (".airlock" in target.parts and not target.is_relative_to(sdk_config))
                or target.name.startswith(".env")
                or target.suffix in {".pem", ".key", ".p12"}
            ):
                refuse("credential.read")
            if (
                not target.is_relative_to(root)
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
