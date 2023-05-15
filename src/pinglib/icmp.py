from __future__ import annotations
import socket
import struct
from asyncio import AbstractEventLoop
from typing import Any, Generator
from . import checksum
import contextlib

_SOCKET_RECEIVE_BUFFER_SIZE = 2048
_SOCKET_TIMEOUT = 1


class AsyncIcmp:
    def __init__(self, skt: socket.socket, loop: AbstractEventLoop):
        self._skt = skt
        self._loop = loop

    @classmethod
    @contextlib.contextmanager
    def new(cls, destination: str, loop: AbstractEventLoop) -> Generator[AsyncIcmp, Any, None]:
        with socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as skt:
            skt.settimeout(_SOCKET_TIMEOUT)
            skt.setblocking(False)
            skt.connect((destination, 0))
            yield AsyncIcmp(skt, loop)

    async def send(self, icmp_type: int, icmp_code: int, rest_of_header: bytes, payload: bytes = bytes()) -> None:
        calculated_checksum = checksum.compute_internet_checksum(struct.pack(
            '>BBH', icmp_type, icmp_code, 0) + rest_of_header + payload)
        await self._loop.sock_sendall(self._skt, struct.pack(
            '>BBH', icmp_type, icmp_code, calculated_checksum) + rest_of_header + payload)

    async def receive(self) -> bytes:
        return await self._loop.sock_recv(self._skt, _SOCKET_RECEIVE_BUFFER_SIZE)
