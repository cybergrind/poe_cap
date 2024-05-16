#!/usr/bin/env python3
import argparse
import asyncio
import logging
import struct

import scapy
from scapy.all import load_layer
from scapy.layers.l2 import Ether


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('tzsp_listener')


def parse_args():
    parser = argparse.ArgumentParser(description='DESCRIPTION')
    parser.add_argument('--port', type=int, default=37009)
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


class UdpProto(asyncio.Protocol):
    def __init__(self, receiver):
        self.receiver = receiver
        self.fragments = {}
        log.debug('init layer')
        load_layer('inet')
        log.debug('loaded ok')

    # ue.payload.payload.payload.load
    def datagram_received(self, data, addr):
        hdr_size = 0x2A - 1
        tags_len = processTag(data[4:])
        hdr_size += tags_len
        ue = Ether(data[4 + tags_len :])
        ip = ue.payload

        log.debug(f'{ip} {ip.version=} {ip.proto=}')
        if ip.version != 4:
            return

        # TCP=6 UDP=17
        if ip.proto != 6:
            return

        # if ip.flags == 1:  # multifragment
        # with open('en.packet', 'w') as f:
        #     f.write(str(data))
        payload = ip.payload
        if ip.flags == 1:
            key = f'{ip.src}=>{ip.dst}'
            if key not in self.fragments:
                self.fragments[key] = {'tcp': payload, 'packets': {}}
            self.fragments[key]['packets'][ip.frag] = payload.load
            return
        elif ip.frag > 0:
            key = f'{ip.src}=>{ip.dst}'
            if key in self.fragments:
                self.fragments[key]['packets'][ip.frag] = payload.load

                payload = self.fragments[key]['tcp']
                ks = sorted(self.fragments[key]['packets'])
                fragments = []
                for k in ks:
                    fragments.append(self.fragments[key]['packets'][k])
                payload = b''.join(fragments)
                import hashlib

                print(f'HASH: {hashlib.md5(payload).hexdigest()}')
                del self.fragments[key]
            else:
                # payload = udp.load
                return
        else:
            log.debug(f'{payload=} => {dir(payload)}')
            if len(payload) == 0:
                return
            if not isinstance(payload.payload, scapy.packet.Raw):
                return
            #payload = payload.load

        # print(f'FLAGS: {ip.flags} => LEN: {ip.len} => FRAG: {ip.frag} SUM: {ip.chksum} / {udp!r}')
        #eft = (16900 <= payload.sport <= 17100) or (16900 <= payload.dport <= 17100)
        #if not eft:
        #    return

        self.receiver(
            {
                'incoming': ip.dst.startswith('192.168.'),
                'data': payload,
                'src_port': payload.sport,
                'dst_port': payload.dport,
            }
        )

        src = read_ip(data, 0x49, hdr_size)
        dst = read_ip(data, 0x4D, hdr_size)
        src_port = read_port(data, 0x51, hdr_size)
        dst_port = read_port(data, 0x53, hdr_size)
        #eft = (16900 <= src_port <= 17100) or (16900 <= dst_port <= 17100)

        # if len(data) > 1519:
        #     print(f'Data len: {len(data)}')
        if len(data) > 0x46 - 0x2A and data[0x46 - 0x2A] == 17:  # UDP
            if len(data) >= 1519:
                print(f'Data: {len(data)}')
                with open('en.packet', 'w') as f:
                    f.write(str(data))
                return

        # print(self.receiver)
        #if not eft:
        #    return

        # print(f'SRC: {src}:{src_port} DST: {dst}:{dst_port} EFT: {eft}')
        #data_offset = 0x59 - 0x2A
        # bprint(data)
        # print(f'LEN: {len(data)} DataOFF: {data_offset}')
        # print(f'{src} => {dst}')
        #rcvd = data[data_offset:]
        rcvd = payload.load
        # print(rcvd)
        # bprint(rcvd[:0x64])
        with open('en2.packet', 'a') as f:
            f.write(str(data))
            f.write('\n')

        self.receiver(
            {
                'incoming': dst.startswith('192.168.'),
                'data': rcvd,
                'src_port': src_port,
                'dst_port': dst_port,
            }
        )


def log_receiver(received):
    log.debug(f'received: {received}')

async def start_server(args):
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UdpProto(log_receiver), local_addr=('0.0.0.0', args.port)
    )
    while True:
        try:
            await asyncio.sleep(120)
        except asyncio.CancelledError:
            log.info('Stopping server')
            break


def main():
    args = parse_args()
    asyncio.run(start_server(args))


if __name__ == '__main__':
    main()
