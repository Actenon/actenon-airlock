"""Linux socket-to-stdio transport. No policy, keys, credentials or execution API.

This standalone stdlib program runs in a separate network-disabled container.
The agent mounts only its socket volume, read-only. The host supervisor receives
data over Docker's attached stdio; macOS/Linux host sockets are never shared.
"""

import json
import os
import socket
import struct
import sys

LIMIT = 8 * 1024 * 1024


def read(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.read(size - len(data))
        if not part:
            raise EOFError
        data.extend(part)
    return bytes(data)


def receive(stream):
    size = struct.unpack("!I", read(stream, 4))[0]
    if size > LIMIT:
        raise ValueError("Message too large")
    value = json.loads(read(stream, size))
    if not isinstance(value, dict):
        raise ValueError("Message must be an object")
    return value


def send(stream, value):
    data = json.dumps(value, separators=(",", ":")).encode() + b"\n"
    if len(data) > LIMIT:
        raise ValueError("Message too large")
    pending = memoryview(struct.pack("!I", len(data)) + data)
    while pending:
        count = stream.write(pending)
        if not count:
            raise EOFError
        pending = pending[count:]
    stream.flush()


def main():
    listener = socket.socket(socket.AF_UNIX)
    listener.bind("/ipc/broker.sock")
    os.chmod("/ipc/broker.sock", 0o666)
    listener.listen(8)
    send(sys.stdout.buffer, {"bridge": "ready", "version": 1})
    while True:
        connection, _ = listener.accept()
        connection.settimeout(40)
        with connection, connection.makefile("rwb", buffering=0) as stream:
            try:
                request = receive(stream)
            except (EOFError, ValueError, TimeoutError):
                continue
            # There is exactly one ordered host request/response at a time.
            send(sys.stdout.buffer, request)
            response = receive(sys.stdin.buffer)
            try:
                send(stream, response)
            except (BrokenPipeError, TimeoutError):
                pass


if __name__ == "__main__":
    main()
