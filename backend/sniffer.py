#!/usr/bin/env python3
import asyncio
import logging
from pathlib import Path

from scapy.all import AsyncSniffer
from scapy.layers.l2 import Ether
from utils import make_hexfriendly


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('sniffer')
PACKET_LOG = Path('en2.packet')


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

        with PACKET_LOG.open('a') as f:
            sdata = str(rcvd)
            hex_friendly = make_hexfriendly(rcvd)
            f.write(f'sport={ip.sport} len={len(sdata)} {hex_friendly}')
            f.write('\n')
            f.write(sdata)
            f.write('\n')


async def start_server():
    proto = POEProto()
    # ports: 12995, 20481, 6112
    filter_str = 'port 12995 or port 20481 or port 6112'
    sniffer = AsyncSniffer(iface='nordlynx', filter=filter_str, prn=proto.process_inner)
    sniffer.start()
    while True:
        try:
            await asyncio.sleep(120)
        except asyncio.CancelledError:
            log.info('Stopping server')
            break


def main():
    if PACKET_LOG.exists():
        PACKET_LOG.unlink()
    asyncio.run(start_server())


if __name__ == '__main__':
    main()
