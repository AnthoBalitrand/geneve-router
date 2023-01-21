from struct import unpack, pack_into


class ICMP:
    """
    ICMP header representation

    |1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Type:           ICMP Message Type (namespace for code)
    Code:           ICMP Message Code for the corresponding Type
    Checksum:       Calculated checksum of the ICMP header
    """

    def __init__(self, rawpacket, start_padding=0):
        unpacked_struct = unpack('!BBH4s')

        self.type = unpacked_struct[0]
        self.code = unpacked_struct[1]
        self.checksum = unpacked_struct[2]
        self.more = unpacked_struct[3]
