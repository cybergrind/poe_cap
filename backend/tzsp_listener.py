#!/usr/bin/env python3
import argparse
import asyncio
import logging
import pathlib
import struct

import scapy
from Crypto.Cipher import Salsa20
from scapy.all import AsyncSniffer, load_layer
from scapy.layers.l2 import Ether


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
handler = logging.FileHandler('tzsp.log')
handler.setLevel(logging.DEBUG)
logging.root.addHandler(handler)

log = logging.getLogger('tzsp_listener')
PACKET_LOG = pathlib.Path('en2.packet')


def parse_args():
    parser = argparse.ArgumentParser(description='DESCRIPTION')
    parser.add_argument('--port', type=int, default=37009)
    parser.add_argument('--iface', default='enp6s0')
    return parser.parse_args()


def read_ip(data, offset, hdr_size):
    real_off = offset - hdr_size
    src_bin = data[real_off : real_off + 4]
    src = f'{src_bin[0]}.{src_bin[1]}.{src_bin[2]}.{src_bin[3]}'
    return src


def read_port(data, offset, hdr_size):
    port_off = offset - hdr_size
    bport = data[port_off : port_off + 2]
    if len(bport) == 0:
        return -1
    return struct.unpack('>H', bport)[0]


def getTagType(type):
    types = {
        0x00: 'TAG_PADDING',
        0x01: 'TAG_END',
        0x0A: 'TAG_RAW_RSSI',
        0x0B: 'TAG_SNR',
        0x0C: 'TAG_DATA_RATE',
        0x0D: 'TAG_TIMESTAMP',
        0x0F: 'TAG_CONTENTION_FREE',
        0x10: 'TAG_DECRYPTED',
        0x11: 'TAG_FCS_ERROR',
        0x12: 'TAG_RX_CHANNEL',
        0x28: 'TAG_PACKET_COUNT',
        0x29: 'TAG_RX_FRAME_LENGTH',
        0x3C: 'TAG_WLAN_RADIO_HDR_SERIAL',
    }
    return types[type]


def processTag(tag, details=False):
    currentTag = None
    i = 0
    while currentTag not in [0x00, 0x01]:
        currentTag = tag[i]
        tagType = getTagType(tag[0])
        tagLength = 0
        if tagType not in ['TAG_END', 'TAG_PADDING']:
            tagLength = ord(tag[1])

        i = i + 1 + tagLength
    return i


def make_hexfriendly(payload: bytes) -> str:
    """
    split per 8, encode as hex values
    """
    out = ['\n']
    cnt = 0
    for i in range(0, len(payload), 8):
        out.append(' '.join([f'{x:02X}' for x in payload[i : i + 8]]))
        cnt += 1
        if cnt % 4 == 0:
            out.append('\n')
    return '    '.join(out)


class POEProto(asyncio.Protocol):
    def __init__(self, receiver):
        self.receiver = receiver
        self.fragments = {}
        self.enc = None
        load_layer('inet')
        log.debug('loaded ok')

    # ue.payload.payload.payload.load
    def datagram_received(self, data, addr):
        # log.debug(f'{data=}')
        hdr_size = 0x2A - 1
        tags_len = processTag(data[4:])
        hdr_size += tags_len
        ue = Ether(data[4 + tags_len :])
        self.process_inner(ue)

    def process_inner(self, ue):
        ip = ue.payload

        # log.debug(f'{ip} {ip.version=} {ip.proto=}')

        if ip.version != 4:
            log.info('skip not ip')
            return

        # TCP=6 UDP=17
        if ip.proto != 6:
            log.info('skip not tcp')
            return

        # if ip.flags == 1:  # multifragment
        payload = ip.payload
        if not isinstance(payload.payload, scapy.packet.Raw):
            # log.info(f'skip not raw: {type(payload.payload)}')
            return

        # payload = payload.load

        # log.debug(f'{ip=}')
        self.receiver(
            {
                'incoming': ip.dst.startswith('192.168.'),
                'data': payload,
                'src_port': payload.sport,
                'dst_port': payload.dport,
            }
        )
        rcvd = payload.load
        # "expand 32-byte k"
        if self.enc is None:
            packet_id = rcvd[:2]
            key, iv = '', ''
            self.enc = Salsa20.new(key=key, nonce=iv)

        with PACKET_LOG.open('a') as f:
            sdata = str(rcvd)
            hex_friendly = make_hexfriendly(rcvd)
            f.write(f'sport={payload.sport} len={len(sdata)} {hex_friendly}')
            f.write('\n')
            f.write(sdata)
            f.write('\n')

        self.receiver(
            {
                'incoming': ip.dst.startswith('192.168.'),
                'data': rcvd,
                'src_port': payload.sport,
                'dst_port': payload.dport,
            }
        )


def log_receiver(received):
    # log.debug(f'received: {received}')
    pass


async def start_server(args):
    # loop = asyncio.get_event_loop()
    # transport, protocol = await loop.create_datagram_endpoint(
    #    lambda: POEProto(log_receiver), local_addr=('0.0.0.0', args.port)
    # )
    proto = POEProto(log_receiver)
    sniffer = AsyncSniffer(iface=args.iface, filter='tcp and port 6112', prn=proto.process_inner)
    sniffer.start()
    while True:
        try:
            await asyncio.sleep(120)
        except asyncio.CancelledError:
            log.info('Stopping server')
            break


def main():
    args = parse_args()
    if PACKET_LOG.exists():
        PACKET_LOG.unlink()
    asyncio.run(start_server(args))


if __name__ == '__main__':
    main()
