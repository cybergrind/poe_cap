import asyncio
import logging

from Crypto.Cipher import Salsa20


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
log = logging.getLogger('test_encrypt')

# hex: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
INITIAL_KEY = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'  # noqa: E501
# hex: B0B1B2B3B4B5B6B7
INITIAL_IV = b'\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7'


class Salsa20Protocol(asyncio.Protocol):
    def __init__(self):
        self.enc = Salsa20.new(key=INITIAL_KEY, nonce=INITIAL_IV)

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        log.debug(f'Received data: {data}')
        out = self.enc.encrypt(data)
        log.debug(f'Encrypted data: {out}')
        self.transport.write(out)

    def connection_lost(self, exc):
        log.debug('Connection lost')


async def start_server(port: int):
    loop = asyncio.get_running_loop()
    server = await loop.create_server(Salsa20Protocol, '0.0.0.0', port)
    return server


async def main():
    server = await start_server(8821)
    await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
