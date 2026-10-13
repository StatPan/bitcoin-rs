#!/usr/bin/env python3
"""Strict, bounded BIP157 regtest probe used by run-compact-filter-interop.py."""

from __future__ import annotations

import hashlib
import math
import socket
import struct
import time

MAGIC = bytes.fromhex("fabfb5da")
FILTER_MESSAGES = {"cfilter", "cfheaders", "cfcheckpt"}


class ProtocolError(RuntimeError):
    """The peer's response cannot satisfy the requested check."""


class CleanEOF(EOFError):
    """Disconnect at a frame boundary, distinct from a truncated frame."""


def require(condition: bool, message: str) -> None:
    # Validation must not disappear under python -O.
    if not condition:
        raise ProtocolError(message)


def sha256d(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()


def compact_size(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def read_compact_size(payload: bytes, offset: int) -> tuple[int, int]:
    require(0 <= offset < len(payload), "missing CompactSize")
    marker = payload[offset]
    if marker < 0xFD:
        return marker, offset + 1
    size, encoding, minimum = {
        0xFD: (2, "<H", 0xFD),
        0xFE: (4, "<I", 0x10000),
        0xFF: (8, "<Q", 0x100000000),
    }[marker]
    require(offset + 1 + size <= len(payload), "truncated CompactSize")
    value = struct.unpack_from(encoding, payload, offset + 1)[0]
    require(value >= minimum, "noncanonical CompactSize")
    return value, offset + 1 + size


def frame(command: str, payload: bytes) -> bytes:
    return (
        MAGIC
        + command.encode("ascii").ljust(12, b"\0")
        + struct.pack("<I", len(payload))
        + sha256d(payload)[:4]
        + payload
    )


class Peer:
    def __init__(self, port: int, *, timeout: float = 30, deadline: float = math.inf):
        require(math.isfinite(timeout) and timeout > 0, "invalid wire timeout")
        self.timeout = timeout
        self.run_deadline = deadline
        self.deadline = min(time.monotonic() + timeout, deadline)
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=self.remaining())
        self.services = None
        try:
            address = struct.pack("<Q", 0) + bytes(16) + struct.pack(">H", port)
            agent = b"/compact-filter-interop/"
            self.send(
                "version",
                struct.pack("<iQq", 70016, 0, int(time.time()))
                + address + address + struct.pack("<Q", time.time_ns() & ((1 << 64) - 1))
                + compact_size(len(agent)) + agent + struct.pack("<i?", 0, False),
            )
            while True:
                command, payload = self.recv()
                if command == "version":
                    require(self.services is None and len(payload) >= 12, "invalid version")
                    self.services = struct.unpack_from("<Q", payload, 4)[0]
                    self.send("verack", b"", reset_deadline=False)
                elif command == "verack":
                    require(self.services is not None and not payload, "invalid verack")
                    break
                elif command in FILTER_MESSAGES:
                    raise ProtocolError("unsolicited filter response during handshake")
        except BaseException:
            self.close()
            raise

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("absolute wire deadline reached")
        return min(10, remaining)

    def exact(self, count: int, *, frame_start: bool = False) -> bytes:
        payload = bytearray()
        while len(payload) < count:
            self.sock.settimeout(self.remaining())
            part = self.sock.recv(count - len(payload))
            if not part:
                if frame_start and not payload:
                    raise CleanEOF("peer disconnected at frame boundary")
                raise ProtocolError("truncated P2P frame before disconnect")
            payload.extend(part)
        return bytes(payload)

    def recv(self) -> tuple[str, bytes]:
        while True:
            header = self.exact(24, frame_start=True)
            require(header[:4] == MAGIC, "wrong network magic")
            length = struct.unpack_from("<I", header, 16)[0]
            require(length <= 4_000_000, "oversized P2P frame")
            raw_command = header[4:16].rstrip(b"\0")
            require(raw_command and all(32 <= byte < 127 for byte in raw_command),
                    "invalid P2P command")
            command = raw_command.decode("ascii")
            payload = self.exact(length)
            require(sha256d(payload)[:4] == header[20:24], "wrong payload checksum")
            if command == "ping":
                require(len(payload) == 8, "invalid ping nonce")
                self.send("pong", payload, reset_deadline=False)
                continue
            return command, payload

    def send(self, command: str, payload: bytes, *, reset_deadline: bool = True) -> None:
        if reset_deadline:
            self.deadline = min(time.monotonic() + self.timeout, self.run_deadline)
        self.sock.settimeout(self.remaining())
        self.sock.sendall(frame(command, payload))

    def wait(self, expected: str) -> bytes:
        while True:
            command, payload = self.recv()
            if command == expected:
                return payload
            require(command not in FILTER_MESSAGES,
                    f"unexpected {command} while waiting for {expected}")

    def barrier(self) -> None:
        # The response stream must end at the expected count. Extra filter frames
        # before this pong are failures, even if their contents are otherwise valid.
        nonce = struct.pack("<Q", time.time_ns() & ((1 << 64) - 1))
        self.send("ping", nonce)
        require(self.wait("pong") == nonce, "wrong barrier nonce")

    def close(self) -> None:
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def run(port: int, rpc, *, deadline: float = math.inf) -> list[str]:
    """Compare nine wire check groups with exact Core RPC filter commitments."""
    hashes = {height: rpc("getblockhash", height) for height in range(2002)}

    def wire(height):
        return bytes.fromhex(hashes[height])[::-1]

    def basic(height):
        return rpc("getblockfilter", hashes[height], "basic")

    with Peer(port, deadline=deadline) as peer:
        require(peer.services & 64, "NODE_COMPACT_FILTERS is absent")
        checks = ["NODE_COMPACT_FILTERS set"]
        peer.send("getcfilters", b"\0" + struct.pack("<I", 1) + wire(1000))
        for height in range(1, 1001):
            payload = peer.wait("cfilter")
            require(len(payload) >= 34 and payload[0] == 0 and payload[1:33] == wire(height),
                    f"wrong cfilter identity at height {height}")
            count, offset = read_compact_size(payload, 33)
            require(offset + count == len(payload), "wrong cfilter length")
            require(payload[offset:].hex() == basic(height)["filter"], "cfilter differs from Core")
        peer.barrier()
        checks.append("1000 sequential cfilters equal Core")

        peer.send("getcfheaders", b"\0" + struct.pack("<I", 1) + wire(2000))
        payload = peer.wait("cfheaders")
        require(len(payload) >= 66 and payload[0] == 0 and payload[1:33] == wire(2000),
                "wrong cfheaders identity")
        require(payload[33:65][::-1].hex() == basic(0)["header"], "wrong previous filter header")
        count, offset = read_compact_size(payload, 65)
        require(count == 2000 and offset + 32 * count == len(payload), "wrong cfheaders count")
        for index in range(count):
            require(payload[offset + 32 * index:offset + 32 * (index + 1)]
                    == sha256d(bytes.fromhex(basic(index + 1)["filter"])),
                    f"filter hash differs from Core at height {index + 1}")
        peer.barrier()
        checks.append("2000 cfheaders hashes and previous header equal Core")

        for height in [0, 999, 1000, 1001, 2000, 2001]:
            peer.send("getcfcheckpt", b"\0" + wire(height))
            payload = peer.wait("cfcheckpt")
            require(len(payload) >= 34 and payload[0] == 0 and payload[1:33] == wire(height),
                    "wrong cfcheckpt identity")
            count, offset = read_compact_size(payload, 33)
            require(count == height // 1000 and offset + 32 * count == len(payload),
                    "wrong checkpoint count")
            for index in range(count):
                require(payload[offset + 32 * index:offset + 32 * (index + 1)][::-1].hex()
                        == basic((index + 1) * 1000)["header"], "checkpoint differs from Core")
            peer.barrier()
        checks.append("checkpoint boundaries 0/999/1000/1001/2000/2001 exact")

    invalid = [
        ("getcfilters", b"\0" + struct.pack("<I", 0) + wire(1000), "1001 filters"),
        ("getcfheaders", b"\0" + struct.pack("<I", 0) + wire(2000), "2001 headers"),
        ("getcfheaders", b"\0" + struct.pack("<I", 1000) + wire(999), "reversed range"),
        ("getcfcheckpt", b"\xff" + wire(1000), "unknown filter type"),
        ("getcfcheckpt", b"\0" + bytes([9]) * 32, "unknown block hash"),
    ]
    for command, payload, label in invalid:
        with Peer(port, deadline=deadline) as peer:
            peer.send(command, payload)
            try:
                while True:
                    response, _ = peer.recv()
                    require(response not in FILTER_MESSAGES,
                            f"{label} emitted {response} before disconnect")
            except CleanEOF:
                checks.append(f"{label}: disconnected without filter response")
    return checks
