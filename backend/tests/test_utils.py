from backend.utils import hex_to_bin


def test_hex_to_bin():
    source = (
        'DB E0 B2 1D C4 42 DE B8    BE CE 02 45 80 3F 7B 74    '
        'EC 24 0F A5 09 F9 53 89    16 98 0A 2E D0 9E 1F 33    '
    )
    dest = (b'\xdb\xe0\xb2\x1d\xc4B\xde\xb8\xbe\xce\x02E\x80?{t'
            b'\xec$\x0f\xa5\t\xf9S\x89\x16\x98\n.\xd0\x9e\x1f3')
    assert hex_to_bin(source) == dest
