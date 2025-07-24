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
        unpacked_struct = unpack('!BBH4s', rawpacket[start_padding:start_padding + 8])

        self.type = unpacked_struct[0]
        self.code = unpacked_struct[1]
        self.checksum = unpacked_struct[2]
        self.more = unpacked_struct[3]
        self.src_port = None
        self.dst_port = None

        self.payload_length = 0
        self.header_end_byte = start_padding + 8

    def repack(self):
        """
        Rebuild a byte-encoded ICMP header
        :return: (bytearray) Byte-encoded packet ICMP header
        """
        repacked_bytes = bytearray(8)

        pack_into('!BBH4s', repacked_bytes, 0, 
            self.type, 
            self.code, 
            self.checksum,
            self.more
            )

        return repacked_bytes

    def __repr__(self):
        return f"[ICMP   Type:{self.type} Code:{self.code}  ]"