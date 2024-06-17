#!/usr/bin/env python3
"""
Find pid of process
"""

import logging

import psutil
from utils import make_hexfriendly
from utils.scanmem import Scanmem


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('memory_scanner')
PROC_NAME = 'PathOfExileStea'
# PROC_NAME = 'main.exe'
KEY_PREFIX = 'expand 32-byte k'


def find_process(proc_name):
    for proc in psutil.process_iter():
        # print(f'{proc.pid=} => {proc.name()} => {proc.cmdline()}')
        if proc.name() == proc_name:
            return proc.pid
    return None


def extract_key(data):
    """
    dwords
    base is 0x10
    """
    base = 0x10
    key_order = [9, 6, 3, 0, 11, 8, 5, 2]
    key = []
    for i in key_order:
        key.append(data[base + i * 4 : base + (i + 1) * 4])
    key = b''.join(key)
    iv_order = [10, 7]
    iv = []
    for i in iv_order:
        iv.append(data[base + i * 4 : base + (i + 1) * 4])
    iv = b''.join(iv)
    print(f'key: {make_hexfriendly(key).strip()}')
    print(f'iv: {make_hexfriendly(iv).strip()}')


def find_by_prefix(pid, prefix):
    """
    use scanmem to find memory adresses by prefix
    """
    scanmem = Scanmem()
    scanmem.send_command(f'pid {pid}')
    scanmem.send_command('reset')
    # noptrace
    scanmem.send_command('option noptrace 1')
    scanmem.send_command('option scan_data_type string')
    scanmem.send_command(f'" {prefix}')
    scanmem.send_command('list')
    values = []
    for _match in scanmem.matches():
        values.append(_match)
        # dump 64 bytes
        dump_cmd = f'dump {_match[1]} 128'
        log.debug(f'{dump_cmd=}')
        data = scanmem.send_command(dump_cmd, get_output=True)
        # print(make_hexfriendly(data))
        extract_key(data)
    return values


def main():
    pid = find_process(PROC_NAME)
    if not pid:
        log.error(f'Process {PROC_NAME} not found')
        return
    adresses = find_by_prefix(pid, KEY_PREFIX)
    log.debug(f'{adresses=}')


if __name__ == '__main__':
    main()
