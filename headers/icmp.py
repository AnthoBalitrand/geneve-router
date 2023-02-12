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

    def __init__(self, rawpacket, start_padding=0, ip_payload_length=0):
        unpacked_struct = unpack('!BBH4s', rawpacket.raw_data[start_padding:start_padding + 8])

        self.type = unpacked_struct[0]
        self.code = unpacked_struct[1]
        self.checksum = unpacked_struct[2]
        self.more = unpacked_struct[3]

        self.payload_length = 0

    def __repr__(self):
        return f"[ICMP   Type:{self.type} Code:{self.code}  ]"