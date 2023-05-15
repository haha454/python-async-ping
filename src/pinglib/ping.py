import asyncio
import itertools
import logging
import math
import struct
import threading
import time
from asyncio import Task, AbstractEventLoop
from dataclasses import dataclass, field
from itertools import count

from .icmp import AsyncIcmp

ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REQUEST_CODE = 0


@dataclass(kw_only=True)
class Response:
    total_length: int
    ttl: int
    icmp_type: int
    icmp_code: int
    checksum: int
    identifier: int
    sequence: int
    source_ip: str
    destination_ip: str
    send_time_us: int
    reply_time_us: int

    def get_rtt_us(self) -> int:
        return self.reply_time_us - self.send_time_us

    def __repr__(self) -> str:
        return f'total_length={self.total_length}|ttl={self.ttl}|icmp_type={self.icmp_type}|' \
               f'icmp_code={self.icmp_code}|ident={self.identifier}|sequence={self.sequence}|' \
               f'source_ip={self.source_ip}|destination_ip={self.destination_ip}|rtt={self.get_rtt_us() / 1000}ms'


@dataclass(kw_only=True)
class ResponseStat:
    count: int = 0
    min_rtt_us: int = -1
    avg_rtt_us: float = 0
    max_rtt_us: int = 0
    _m2_us: int = 0

    def reset(self) -> None:
        self.count = 0
        self.min_rtt_us = -1
        self.avg_rtt_us = 0
        self.max_rtt_us = 0
        self._m2_us = 0

    def get_std_rtt_us(self) -> float:
        return math.nan if self.count < 2 else self._m2_us / self.count - 1

    def add_rtt(self, rtt_us: int) -> None:
        self.min_rtt_us = rtt_us if self.min_rtt_us == -1 else min(self.min_rtt_us, rtt_us)
        self.max_rtt_us = max(self.max_rtt_us, rtt_us)
        # https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
        self.count += 1
        delta = rtt_us - self.avg_rtt_us
        self.avg_rtt_us += delta / self.count
        self._m2_us += delta * (rtt_us - self.avg_rtt_us)

    def __repr__(self):
        return f'{self.count} packets received, rtt min/avg/max/mdev = ' \
               f'{self.min_rtt_us / 1000:.3f}/{self.avg_rtt_us / 1000:.3f}/' \
               f'{self.max_rtt_us / 1000:.3f}/{self.get_std_rtt_us() / 1000000:.3f} ms'


@dataclass
class Ping:
    destination: str
    loop: AbstractEventLoop = field(default_factory=lambda: asyncio.get_running_loop())
    requests_count: int = field(default=0, init=False)
    response_stat: ResponseStat = field(default_factory=ResponseStat, init=False)

    async def exec(self, *, times: int = 0, interval_sec: float = 1):
        if interval_sec < 0.01:
            raise ValueError('cannot flood; minimal interval allowed for user is 10ms')
        self.requests_count = 0
        self.response_stat.reset()

        with AsyncIcmp.new(self.destination, self.loop) as session:
            ident: int = threading.get_native_id() & 0xFFFF
            seq_iter = count() if times == 0 else range(times)
            icmp_recv_tasks: set[Task] = set()
            for seq in seq_iter:
                await self._send_one_ping_request(ident, seq, session)
                icmp_recv_tasks.add(asyncio.create_task(self._receive_one_ping_response(session)))
                interval_sleep_task = asyncio.create_task(asyncio.sleep(interval_sec))
                finished_tasks, pending_tasks = await asyncio.wait(
                    itertools.chain(icmp_recv_tasks, [interval_sleep_task]),
                    return_when=asyncio.FIRST_COMPLETED)

                assert finished_tasks
                for finished_task in finished_tasks:
                    if finished_task != interval_sleep_task:
                        response = await finished_task
                        yield response
                await interval_sleep_task
                icmp_recv_tasks = pending_tasks
                icmp_recv_tasks.discard(interval_sleep_task)
                logging.info('number of icmp_recv_tasks %d', len(icmp_recv_tasks))

            for icmp_recv_task in icmp_recv_tasks:
                icmp_recv_task.cancel()

    async def _send_one_ping_request(self, ident, seq, session):
        await session.send(ICMP_ECHO_REQUEST_TYPE, ICMP_ECHO_REQUEST_CODE, struct.pack('>HH', ident, seq),
                           struct.pack('>Q', self._get_current_time_in_ns()))
        self.requests_count += 1

    async def _receive_one_ping_response(self, session: AsyncIcmp) -> Response:
        received_bytes = await session.receive()
        assert (received_bytes[0] == 0x45)
        total_length, = struct.unpack('>H', received_bytes[2:4])
        ttl = received_bytes[8]
        source_ip_bytes, destination_ip_bytes = received_bytes[12:16], received_bytes[16:20]
        icmp_type, icmp_code, checksum, identifier, sequence = struct.unpack(
            '>BBHHH', received_bytes[20:28])
        payload = received_bytes[28:]
        response = Response(total_length=total_length, ttl=ttl, icmp_type=icmp_type, icmp_code=icmp_code,
                            checksum=checksum,
                            identifier=identifier, sequence=sequence,
                            source_ip=".".join(map(str, source_ip_bytes)),
                            destination_ip=".".join(map(str, destination_ip_bytes)),
                            send_time_us=struct.unpack('>Q', payload)[0],
                            reply_time_us=self._get_current_time_in_ns(), )
        self.response_stat.add_rtt(response.get_rtt_us())

        return response

    @classmethod
    def _get_current_time_in_ns(cls) -> int:
        return int(time.time() * 1000000)
