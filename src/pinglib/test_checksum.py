from .checksum import compute_internet_checksum


def test_compute_internet_checksum():
    assert compute_internet_checksum(b'\x00\x01\xf2\x03\xf4\xf5\xf6\xf7') == 8717
