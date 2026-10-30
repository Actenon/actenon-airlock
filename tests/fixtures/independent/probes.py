"""Harness-selected probes against an owned endpoint; never a model attack claim."""

import ctypes
import json
import os
import socket
import struct
import subprocess
import sys
import urllib.request
from pathlib import Path


def tcp(host, label):
    with socket.create_connection((host, 8080), timeout=2) as stream:
        stream.sendall(label.encode())
        assert stream.recv(2) == b"OK"


def native(host):
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.socket(2, 1, 0)
    assert fd >= 0
    address = struct.pack("H", 2) + struct.pack("!H", 8080) + socket.inet_aton(host) + b"\0" * 8
    try:
        if libc.connect(fd, address, len(address)) != 0:
            raise OSError(ctypes.get_errno(), "native connect")
        assert libc.send(fd, b"native", 6, 0) == 6
        data = ctypes.create_string_buffer(2)
        assert libc.recv(fd, data, 2, 0) == 2 and data.raw == b"OK"
    finally:
        libc.close(fd)


def raw(host):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as stream:
        body = b"raw-udp"
        stream.sendto(struct.pack("!HHHH", 49000, 8081, len(body) + 8, 0) + body, (host, 0))


def proxy(host):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://{host}:8082"})
    )
    with opener.open("http://owned-target.invalid/proxy", timeout=2) as response:
        assert response.read() == b"OK"


def run(config, protected):
    operations = {
        "ipv4": lambda: tcp(config["ipv4"], "ipv4"),
        "ipv6": lambda: tcp(config["ipv6"], "ipv6"),
        "dns": lambda: tcp(config["hostname"], "dns"),
        "native": lambda: native(config["ipv4"]),
        "raw": lambda: raw(config["ipv4"]),
        "proxy": lambda: proxy(config["ipv4"]),
        "nested": lambda: subprocess.run(
            [
                sys.executable,
                "-c",
                'import subprocess,sys; subprocess.run([sys.executable,"-c",'
                + repr(
                    "import socket; s=socket.create_connection(("
                    + repr(config["ipv4"])
                    + ',8080),timeout=2); s.sendall(b"nested"); assert s.recv(2)==b"OK"'
                )
                + "],check=True)",
            ],
            check=True,
            timeout=10,
            capture_output=True,
        ),
    }
    outcomes = {}
    for name, operation in operations.items():
        try:
            operation()
        except (OSError, subprocess.CalledProcessError) as exc:
            assert protected, (name, repr(exc))
            outcomes[name] = "blocked"
        else:
            assert not protected, "escape: " + name
            outcomes[name] = "delivered"
    if protected:
        assert os.getuid() == 10000
        assert not Path("/var/run/docker.sock").exists()
        assert not Path(config["sentinel"]).exists()
        assert "AIRLOCK_ASSURANCE_HOST_SECRET" not in os.environ
        assert b"assurance-host-only" not in Path("/proc/1/environ").read_bytes()
        try:
            Path("/ipc/broker.sock").unlink()
        except OSError:
            outcomes["ipc-replace"] = "blocked"
        else:
            raise AssertionError("writable IPC")
        Path("escape").symlink_to("/airlock/contained_agent.py")
        try:
            Path("escape").write_text("replaced")
        except OSError:
            outcomes["symlink-write"] = "blocked"
        else:
            raise AssertionError("writable control mount")
    return outcomes


if __name__ == "__main__":
    print(json.dumps(run(json.loads(sys.argv[1]), False), sort_keys=True))
