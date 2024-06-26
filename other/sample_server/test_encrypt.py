#!/usr/bin/env python3
import argparse
import logging
import base64
# import salsa20
from Crypto.Cipher import Salsa20


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('test_encrypt')

# hex: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
INITIAL_KEY = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
# hex: B0B1B2B3B4B5B6B7
INITIAL_IV = b'\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7'

PHRASE = 'Hello, World!22'
SAMPLE_B64_out = b'ZshjM3d7CZm5AN/NCQ=='
SAMPLE_B64_out = b'ZshjM3d7CZm5'
SAMPLE_B64_out = b'smDVI8VSmyE1Wiwcq/Ohp'

def main():
    enc = Salsa20.new(key=INITIAL_KEY, nonce=INITIAL_IV)
    out = enc.encrypt(PHRASE.encode())

    log.debug(f'{out=}')
    log.debug(f'{base64.b64encode(out)=}')

    # decrypt
    dec = Salsa20.new(key=INITIAL_KEY, nonce=INITIAL_IV)
    dec_out = dec.decrypt(base64.b64decode(SAMPLE_B64_out))
    log.debug(f'{dec_out=}')
    dec_out = dec.decrypt(base64.b64decode(SAMPLE_B64_out))
    log.debug(f'{dec_out=}')

if __name__ == '__main__':
    main()

