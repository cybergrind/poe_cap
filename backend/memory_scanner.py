#!/usr/bin/env python3
"""
Find pid of process
"""
import psutil
import logging
from utils import make_hexfriendly
from utils.scanmem import Scanmem


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('memory_scanner')
PROC_NAME = 'PathOfExileStea'
KEY_PREFIX = 'expand 32-byte k'


def find_process(proc_name):
    for proc in psutil.process_iter():
        #print(f'{proc.pid=} => {proc.name()} => {proc.cmdline()}')
        if proc.name() == proc_name:
            return proc.pid
    return None


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
        print(make_hexfriendly(data))
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
