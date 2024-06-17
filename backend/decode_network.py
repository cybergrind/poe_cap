#!/usr/bin/env python3
import argparse
import logging
from base64 import b64decode
from pathlib import Path

from Crypto.Cipher import Salsa20

from backend.utils import hex_to_bin, make_hexfriendly


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('decode_network')
BASE_DIR = Path('decode').resolve()
FILES = ['20481.log', '6112.log']

KEY_CANDIDATES = """
key: 3C 61 70 70 59 50 54 4F    72 20 78 38 00 43 68 61    70 65 6E 73 20 62 79 20    2C 20 43 52 30 20 66 6F
iv: 72 6F 40 6F 47 41 4D 53
key: 18 1C 73 84 FC 27 C9 2B    CB 9F F7 35 95 54 2F 50    D2 04 45 91 87 FB A1 83    94 8B 9C 03 10 F7 0A 0D
iv: FF 3C 58 A9 A2 24 95 5E
key: 18 1C 73 84 FC 27 C9 2B    CB 9F F7 35 95 54 2F 50    D2 04 45 91 87 FB A1 83    94 8B 9C 03 10 F7 0A 0D
iv: 49 2F A5 5D AD 93 0D 99
key: 1E 1C 5E AD 41 45 20 55    5E EA 40 8B 85 78 3F DD    7B 1D 9D 92 BC B3 26 31    7D 98 56 38 66 CA 3F B0
iv: 33 62 3C 30 99 23 71 22
key: 1E 1C 5E AD 41 45 20 55    5E EA 40 8B 85 78 3F DD    7B 1D 9D 92 BC B3 26 31    7D 98 56 38 66 CA 3F B0
iv: AB 0A CB E7 28 68 C9 42
key: F3 DE 44 09 B3 73 B5 C2    FF 85 96 D6 79 B9 6D 61    82 14 BD DA 59 8C BE FF    6F 2D 9A 03 89 40 8C 08
iv: 60 84 88 68 8D E9 52 7B
key: F3 DE 44 09 B3 73 B5 C2    FF 85 96 D6 79 B9 6D 61    82 14 BD DA 59 8C BE FF    6F 2D 9A 03 89 40 8C 08
iv: 15 C4 C8 C6 28 1E D9 FF
key: 00 00 00 00 0D 54 D1 13    CF 4F 6D CB 1B 03 4F E6    00 00 00 00 02 00 00 00    2C 17 84 11 2B CB 40 01
iv: D8 23 70 66 59 6B DC A7
key: 00 00 00 00 25 84 64 17    3D 68 4C 15 D1 6B 03 D9    00 00 00 00 01 00 00 00    34 D3 03 1A 12 69 3C 58
iv: D8 23 70 66 23 2F 58 77
key: 00 00 00 00 85 80 85 BA    A1 6F 56 62 10 9E 5F 5D    00 00 00 00 02 00 00 00    CE 69 19 10 84 B4 53 AA
iv: CF 23 70 66 B5 46 16 05
key: 00 00 00 00 35 C4 4E 1E    78 AA A2 19 E4 C6 03 B4    00 00 00 00 01 00 00 00    E1 70 8C 80 57 ED 38 03
iv: CF 23 70 66 D4 30 9B AB
"""


def gen_key_iv():
    key, iv = None, None
    counter = 0
    for line in KEY_CANDIDATES.splitlines():
        if not line:
            continue
        if 'key' in line:
            key = hex_to_bin(line.split(': ')[1].replace(' ', ''))
        if 'iv' in line:
            iv = hex_to_bin(line.split(': ')[1].replace(' ', ''))
            yield counter, key, iv
            counter += 1


def try_to_decode_network(line, args):
    """
    line format:
    sport=47732 dport=6112 buffer='eiNpPEU+30I0dA=='
    """
    log.debug(f'Try to decode: {line}')
    sport, dport, buffer = line.split()
    buffer = b64decode(buffer.split("'")[1])[args.skip_bytes :]
    log.debug(f'\n{make_hexfriendly(buffer, xxd=True)}')
    for counter, key, iv in gen_key_iv():
        log.debug(f'{counter=} {key=}')
        dec = Salsa20.new(key=key, nonce=iv).decrypt(buffer)
        log.debug(f'\n{make_hexfriendly(dec, xxd=True)}')


def get_args():
    parser = argparse.ArgumentParser(description='Decode network packets')
    parser.add_argument('file', type=Path)
    parser.add_argument('position', type=int, default=0, nargs='?')
    parser.add_argument('--skip-bytes', type=int, default=0)
    parser.add_argument('--use-key', type=int, default=None)
    return parser.parse_args()


def main():
    args = get_args()
    with args.file.open() as f:
        lines = f.readlines()
        line = lines[args.position]
        try_to_decode_network(line, args)


if __name__ == '__main__':
    main()
