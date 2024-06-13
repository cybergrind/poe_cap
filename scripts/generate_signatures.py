#!/usr/bin/env python3
import argparse
import logging
import os
from contextlib import suppress
from functools import wraps
from pathlib import Path

from fabric import Connection
from fan_tools.unix import ExecError, cd, succ


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('generate_signatures')

LIBS_DIR = Path('static_libs').resolve()
LIBS_DIR.mkdir(exist_ok=True)
SIGNATURES_DIR = LIBS_DIR / 'signatures'
SIGNATURES_DIR.mkdir(exist_ok=True)

INFO = ['paramiko', 'fabric', 'invoke']
for name in INFO:
    logging.getLogger(name).setLevel(logging.INFO)
WARN = ['paramiko.transport']
for name in WARN:
    logging.getLogger(name).setLevel(logging.WARN)


VERSION_TAGS = [
    #    'CRYPTOPP_5_0',
    #    'CRYPTOPP_5_1',
    #    'CRYPTOPP_5_2',
    #    'CRYPTOPP_5_2_1',
    #    'CRYPTOPP_5_2_3',
    #    'CRYPTOPP_5_3_0',
    #    'CRYPTOPP_5_4',
    #    'CRYPTOPP_5_5',
    #    'CRYPTOPP_5_5_1',
    #    'CRYPTOPP_5_5_2',
    #    'CRYPTOPP_5_6_0',
    #    'CRYPTOPP_5_6_1',
    #    'CRYPTOPP_5_6_2',
    #    'CRYPTOPP_5_6_3',
    #    'CRYPTOPP_5_6_4',
    #    'CRYPTOPP_5_6_5',
    'CRYPTOPP_6_0_0',
    'CRYPTOPP_6_1_0',
    'CRYPTOPP_7_0_0',
    'CRYPTOPP_8_0_0',
    'CRYPTOPP_8_1_0',
    'CRYPTOPP_8_2_0',
    'CRYPTOPP_8_3_0',
    'CRYPTOPP_8_4_0',
    'CRYPTOPP_8_5_0',
    'CRYPTOPP_8_6_0',
    'CRYPTOPP_8_7_0',
    'CRYPTOPP_8_8_0',
    'CRYPTOPP_8_9_0',
]


def parse_args():
    parser = argparse.ArgumentParser(description='DESCRIPTION')
    parser.add_argument('-w', '--windows-host', default=os.getenv('WIN_HOST'))
    parser.add_argument('--cwd', default='devel/poe_cap/external/cryptopp')
    parser.add_argument(
        '--flair-bin',
        default=os.getenv('FLAIR_BIN'),
        type=lambda x: Path(x).resolve(),
        help='directory with flair binaries [sigmake, pcf]',
    )
    return parser.parse_args()


def run_wrapper(args):
    args.conn = Connection(args.windows_host)
    conn = args.conn
    log.debug(f'CWD: {args.cwd}')

    # need intermediate value because conn.cd() immediately deleted otherwise
    args.ccc = ccc = conn.cd(args.cwd)
    ccc.__enter__()

    @wraps(conn.run)
    def _run(cmd, *__args, msg=None, **__kwargs):
        if msg:
            log.info(f'{msg}: {cmd}')
        else:
            log.debug(f'Run: {cmd}')
        return conn.run(cmd, *__args, **__kwargs)

    args.run = _run


def build_tag(args, tag):
    args.run('git reset HEAD --hard')
    args.run(f'git checkout {tag}')
    args.run('git clean -xfd')
    args.run('msbuild cryptlib.vcxproj /p:Configuration=Release /p:Platform=x64')
    # download x64/Output/Release/cryptlib.lib => static_libs/cryptlib_<version>.lib
    args.conn.get(f'{args.cwd}/x64/Output/Release/cryptlib.lib', f'static_libs/cryptlib_{tag}.lib')


def generate_signature(args, tag):
    with cd(args.flair_bin):
        src_lib = LIBS_DIR / f'cryptlib_{tag}.lib'
        pat_file = LIBS_DIR / f'cryptlib_{tag}.pat'
        exc_file = LIBS_DIR / f'cryptlib_{tag}.exc'
        sig_file = LIBS_DIR / f'cryptlib_{tag}.sig'

        to_unlink = [exc_file, pat_file, sig_file]
        for f in to_unlink:
            if f.exists():
                f.unlink()

        succ(f'./pcf {src_lib} {pat_file}')

        with suppress(ExecError):
            succ(f'./sigmake {pat_file} {sig_file}', check_stderr=False)

        exc_content = exc_file.read_text().split('\n')
        exc_file.write_text('\n'.join(exc_content[4:]))
        succ(f'./sigmake {pat_file} {sig_file}')
        exc_file.unlink()
        sig_file.rename(SIGNATURES_DIR / f'cryptlib_{tag}.sig')
        pat_file.rename(SIGNATURES_DIR / f'cryptlib_{tag}.pat')


def main():
    args = parse_args()
    run_wrapper(args)

    args.run('pwd')
    for tag in VERSION_TAGS:
        build_tag(args, tag)
        generate_signature(args, tag)


if __name__ == '__main__':
    main()
