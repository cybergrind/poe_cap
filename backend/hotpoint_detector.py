#!/usr/bin/env python3
"""
run command in shell:
gdb -p $(pgrep PathOfExileStea) --batch --ex "thread apply all bt" --ex detach | ag PathOfExileSteam.exe

output:
0x0000000141922e28 in ?? () from target:/mnt/extra2/extra_1000/games/SteamLibrary/steamapps/common/Path of Exile/PathOfExileSteam.exe
#0  0x000000014249f3e3 in ?? () from target:/mnt/extra2/extra_1000/games/SteamLibrary/steamapps/common/Path of Exile/PathOfExileSteam.exe
#0  0x00000001422e527b in ?? () from target:/mnt/extra2/extra_1000/games/SteamLibrary/steamapps/common/Path of Exile/PathOfExileSteam.exe
#0  0x0000000141922e28 in ?? () from target:/mnt/extra2/extra_1000/games/SteamLibrary/steamapps/common/Path of Exile/PathOfExileSteam.exe

then extract and count adresses and write top adresses.
"""

import logging
import time
from subprocess import run


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('hotpoint_detector')
# 'gdb -p $(pgrep PathOfExileStea) --batch --ex "thread apply all bt" --ex detach'
CMD = 'gdb -p $(pgrep PathOfExileStea) --batch --ex "bt" --ex detach' ' | ag PathOfExileSteam.exe'


def find_adresses(cmd, addresses: dict):
    result = run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        log.error(f'Error: {result.stderr}')
        return
    lines = result.stdout.split('\n')
    for line in lines:
        if not line:
            continue
        candidates = line.split()

        if len(candidates) > 1:
            for address in candidates[:2]:
                if address.startswith('0x'):
                    addresses[address] = addresses.get(address, 0) + 1
    return addresses


def print_topn(addresses, topn=10):
    sorted_addresses = sorted(addresses.items(), key=lambda x: x[1], reverse=True)
    for address, count in sorted_addresses[:topn]:
        if count == 1:
            continue
        log.info(f'{address}: {count}')
    print('=' * 80)


def main():
    addresses = {}
    while True:
        find_adresses(CMD, addresses)
        print_topn(addresses, 5)
        time.sleep(1)


if __name__ == '__main__':
    main()
