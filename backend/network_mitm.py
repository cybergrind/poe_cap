#!/usr/bin/env python3
import asyncio
import logging
from base64 import b64decode
from contextlib import contextmanager, suppress
from pathlib import Path

from fan_tools.unix import succ


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('network_mitm ')

PACKET_DIR = Path('packet_dump')
PORTS = {12995, 20481, 6112}
MAPPING = {
    12995: 19495,
    20481: 19481,
    6112: 19412,
}


@contextmanager
def iptables_reroute():
    for sport, dport in MAPPING.items():
        # with comment: poe
        # redirect to dport on localhost
        cmd = (
            f'iptables -t nat -A OUTPUT -p tcp --dport {sport} '
            f'-j DNAT --to-destination 127.0.0.1:{dport} '
            '-m comment --comment poe'
        )
        logging.debug(f'Executing: {cmd}')
        code, _, _err = succ(cmd)
        if code:
            raise Exception(f'Error: {code} {_err}')
    with suppress(BaseException):
        yield
    # drop by comment
    cmd = 'iptables -t nat -L PREROUTING --line-numbers'
    code, out, _err = succ(cmd)
    for line in out[::-1]:
        if 'poe' in line:
            num = line.split()[0]
            cmd = f'iptables -t nat -D PREROUTING {num}'
            logging.debug(f'Executing: {cmd}')
            code, _, _err = succ(cmd)
            if code:
                raise Exception(f'Error: {code} {_err}')

    cmd = 'iptables -t nat -L OUTPUT --line-numbers'
    code, out, _err = succ(cmd)
    for line in out[::-1]:
        if 'poe' in line:
            num = line.split()[0]
            cmd = f'iptables -t nat -D OUTPUT {num}'
            logging.debug(f'Executing: {cmd}')
            code, _, _err = succ(cmd)
            if code:
                raise Exception(f'Error: {code} {_err}')


class POEProto(asyncio.Protocol):
    def __init__(self, port):
        self.port = port
        self.packets_file = PACKET_DIR / f'{port}.log'
        self.handler = self.packets_file.open()

    def connection_made(self, transport: asyncio.transports.Transport) -> None:
        self.transport = transport
        self.handler.close()
        self.handler = self.packets_file.open()
        self.handler.readline()
        log.debug(f'connection made {self.port=} {id(self)=}')

    def write_next_packet(self):
        # sport=59248 dport=20481 buffer='<BASE64>'
        while True:
            line = self.handler.readline()
            print(f'{line=}')
            if not line:
                return None
            sport, dport, buffer = line.split()
            if sport == f'sport={self.port}':
                buff = buffer.split("'")[1]
                packet = b64decode(buff)
                self.transport.write(packet)
            else:
                break

    def data_received(self, data: bytes) -> None:
        log.debug(f'received: {data=}')
        self.write_next_packet()


async def start_server():
    servers = {}
    for port, dport in MAPPING.items():
        servers[port] = await asyncio.get_event_loop().create_server(
            lambda: POEProto(port),
            host='0.0.0.0',
            port=dport,
        )
    while True:
        await asyncio.sleep(60)


def main():
    with iptables_reroute():
        asyncio.run(start_server())


if __name__ == '__main__':
    main()
