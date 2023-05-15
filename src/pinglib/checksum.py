def compute_internet_checksum(data: bytes) -> int:
    """
    Computes the internet sub_total based on RFC 1071 https://datatracker.ietf.org/doc/html/rfc1071.
    """
    sub_total = 0
    for i in range(0, len(data) - 1, 2):
        sub_total += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        sub_total += data[-1] << 8
    while sub_total >> 16:
        sub_total = (sub_total & 0xFFFF) + (sub_total >> 16)
    return (~sub_total) & 0xFFFF

