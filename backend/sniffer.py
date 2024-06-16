#!/usr/bin/env python3
import asyncio
import logging
from base64 import b64encode
from pathlib import Path

from fan_tools.unix import succ
from scapy.all import AsyncSniffer
from scapy.layers.l2 import Ether


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('sniffer')
PACKET_DIR = Path('packet_dump')
PACKET_DIR.mkdir(exist_ok=True)
PORTS = {12995, 20481, 6112}


def get_main_interface():
    cmd = 'ip route get 1.1.1.1'
    out = succ(cmd)[1]
    for line in out:
        if 'dev' in line:
            return line.split()[2]
    raise NotImplementedError


class POEProto(asyncio.Protocol):
    def __init__(self):
        pass

    # ue.payload.payload.payload.load
    def datagram_received(self, data, addr):
        # log.debug(f'{data=}')
        hdr_size = 0x2A - 1
        tags_len = processTag(data[4:])
        hdr_size += tags_len
        ue = Ether(data[4 + tags_len :])
        self.process_inner(ue)

    def process_inner(self, ue: Ether):
        ip = ue.payload
        payload = ip.payload
        if not payload:
            return
        rcvd = payload.load
        log.debug(f'{ip=}')

        port_name = ip.sport if ip.sport in PORTS else ip.dport
        log_file = PACKET_DIR / f'{port_name}.log'

        with log_file.open('a') as f:
            buffer = b64encode(rcvd).decode()
            f.write(f'sport={ip.sport} dport={ip.dport} {buffer=}')
            f.write('\n')



async def start_server():
    proto = POEProto()
    # ports: 12995, 20481, 6112
    filter_str = ' or '.join(f'port {port}' for port in PORTS)

    sniffer = AsyncSniffer(iface=get_main_interface(), filter=filter_str, prn=proto.process_inner)
    sniffer.start()
    while True:
        try:
            await asyncio.sleep(120)
        except asyncio.CancelledError:
            log.info('Stopping server')
            break


def main():
    asyncio.run(start_server())


if __name__ == '__main__':
    main()
