#!/usr/bin/env python3
"""
usage:

./scripts/gdb_break.py 0x141893d3f
"""
import argparse
import logging
import subprocess
import shlex


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('gdb_break')

DEBUG_SYMBOLS = '/home/kpi/devel/github/poe_cap/poe_annotated.debug'
PROC_NAME = 'PathOfExileStea'
NO_USR1 = ['--ex', 'handle SIGUSR1 noprint nostop']
FIND_PID = ['pgrep', PROC_NAME]
AFTER_BREAKPOINT = ['--ex', 'info b', '--ex', 'bt', '--ex', 'info r']
END = ['--ex', 'detach']


def breakpoint_processor(s):
    """
    valid:
    address
    *address
    b *address
    catch syscall <name>
    """
    if s.startswith('0x'):
        return f'b *{s}'
    if s.startswith('*'):
        return f'b {s}'
    return s


def parse_args():
    parser = argparse.ArgumentParser(description='DESCRIPTION')
    parser.add_argument('breakpoint', type=breakpoint_processor)
    parser.add_argument('-c', '--condition', default=None)
    # flag
    parser.add_argument('--r8', action='store_true')
    parser.add_argument('--r9', action='store_true')
    parser.add_argument('--rax', action='store_true')
    parser.add_argument('--rbp', action='store_true')
    parser.add_argument('--rcx', action='store_true')
    parser.add_argument('--rdx', action='store_true')
    parser.add_argument('--rsi', action='store_true')
    parser.add_argument('--usr1', action='store_true')
    parser.add_argument('-s', '--stack', action='store_true')
    return parser.parse_args()


def main():
    args = parse_args()
    pid = subprocess.check_output(FIND_PID).decode().strip()
    if not pid:
        log.error(f'Process {PROC_NAME} not found')
        return
    cmd = ['/usr/bin/gdb', '-p', pid, '--batch', '--ex', f'add-symbol-file {DEBUG_SYMBOLS}']
    if not args.usr1:
        cmd.extend(NO_USR1)
    cmd.extend(['--ex', args.breakpoint, '--ex', 'c'])
    if args.condition:
        cmd.extend(['--ex', f'condition 1 {args.condition}'])

    cmd.extend(AFTER_BREAKPOINT)
    if args.stack:
        cmd.extend(['--ex', 'x /30x $rsp'])

    for reg in ['rsi', 'rcx', 'rax', 'rbp', 'rdx', 'r8', 'r9']:
        if getattr(args, reg):
            cmd.extend(['--ex', f'xxd ${reg} 64'])

    cmd.extend(END)
    cmd = ' '.join([shlex.quote(x) for x in cmd])
    print(f'{cmd=}')

    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    stdout, stderr = res.stdout, res.stderr
    for line in stdout.split('\n'):
        # filter [New LWP 2944872]
        if line.startswith('[New LWP'):
            continue
        if line.startswith('No symbol table'):
            continue
        print(line)

    print(f'='*80)
    for line in stderr.split('\n'):
        print(line)


if __name__ == '__main__':
    main()
