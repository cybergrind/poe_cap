#!/usr/bin/env python3
"""
Find pid of process
"""
import sys
import logging
import argparse

import psutil
from utils import make_hexfriendly
from utils.scanmem import Scanmem


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('memory_scanner')
PROC_NAME = 'PathOfExileStea'
KEY_PREFIX = 'expand 32-byte k'


def convert_address(addr):
    if ' ' in addr:
            addr = ''.join(reversed(addr.split()))
            addr = '0x' + addr.replace(' ', '')
    return addr


def parse_args():
    parser = argparse.ArgumentParser(description='address')
    parser.add_argument('addr', nargs='?', help='address to dump', type=convert_address)
    parser.add_argument('-s', '--size', default=1024, help='size to dump', type=int)
    return parser.parse_args()


def find_process(proc_name):
    for proc in psutil.process_iter():
        # print(f'{proc.pid=} => {proc.name()} => {proc.cmdline()}')
        if proc.name() == proc_name:
            return proc.pid
    return None


def dump(pid, address, size=256):
    """
    use scanmem to dump memory
    """
    scanmem = Scanmem()
    scanmem.send_command(f'pid {pid}')
    scanmem.send_command('reset')
    # noptrace
    scanmem.send_command('option noptrace 1')
    dump_cmd = f'dump {address} {size}'
    data = scanmem.send_command(dump_cmd, get_output=True)
    print(make_hexfriendly(data))
    return data


def main():
    args = parse_args()
    pid = find_process(PROC_NAME)
    if not pid:
        log.error(f'Process {PROC_NAME} not found')
        return
    print(f'dump {args.addr=}')
    dump(pid, hex(int(args.addr, 16)), args.size)
    print('=' * 80)


if __name__ == '__main__':
    main()
