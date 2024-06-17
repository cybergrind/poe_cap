from fan_tools.unix import succ
from tempfile import NamedTemporaryFile

def make_hexfriendly(payload: bytes, xxd=False) -> str:
    """
    split per 8, encode as hex values
    """
    if xxd:
        with NamedTemporaryFile() as f:
            f.write(payload)
            f.flush()
            cmd = f'xxd -g 1 {f.name}'
            code, output, err = succ(cmd)
            return '\n'.join(output)
    out = ['']
    cnt = 0
    for i in range(0, len(payload), 8):
        out.append(' '.join([f'{x:02X}' for x in payload[i : i + 8]]))
        cnt += 1
        if cnt % 4 == 0:
            out.append('\n')
    return '    '.join(out)


def hex_to_bin(s: str) -> bytes:
    """
    convert hex string to binary
    example string: 3C 61 70 70 59 50 54 4F    72 20 78 38 00 43 68 61
                    70 65 6E 73 20 62 79 20    2C 20 43 52 30 20 66 6F
    """
    return bytes.fromhex(s.replace(' ', ''))
