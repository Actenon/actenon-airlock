"""Bounded, length-prefixed messages over an inherited local socket."""

import json
import struct

LIMIT = 8 * 1024 * 1024


def send(sock, value):
    data = json.dumps(value, separators=(",", ":")).encode()
    if len(data) > LIMIT:
        raise ValueError("Airlock message exceeds 8 MiB")
    sock.sendall(struct.pack("!I", len(data)) + data)


def receive(sock):
    def read(size):
        data = bytearray()
        while len(data) < size:
            part = sock.recv(size - len(data))
            if not part:
                raise EOFError("Airlock broker connection closed")
            data.extend(part)
        return bytes(data)

    size = struct.unpack("!I", read(4))[0]
    if size > LIMIT:
        raise ValueError("Airlock message exceeds 8 MiB")
    value = json.loads(read(size))
    if not isinstance(value, dict):
        raise ValueError("Airlock message must be an object")
    return value
