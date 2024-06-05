def make_hexfriendly(payload: bytes) -> str:
    """
    split per 8, encode as hex values
    """
    out = ['\n']
    cnt = 0
    for i in range(0, len(payload), 8):
        out.append(' '.join([f'{x:02X}' for x in payload[i : i + 8]]))
        cnt += 1
        if cnt % 4 == 0:
            out.append('\n')
    return '    '.join(out)
