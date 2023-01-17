from struct import unpack, pack_into


class UDP:
    """
    UDP header representation

    |1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Length             |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, rawpacket, start_padding=0):
        unpacked_struct = unpack('!HHHH', rawpacket.raw_data[start_padding:])

        self.src_port = unpacked_struct[0]
        self.dst_port = unpacked_struct[1]
        self.length = unpacked_struct[2]
        self.checksum = unpacked_struct[3]

    def swap_ports(self):
        self.src_port, self.dst_port = self.dst_port, self.src_port

    def repack(self):
        repacked_bytes = bytearray(8)

        pack_into('!HHHH', repacked_bytes, 0,
                  self.src_port,
                  self.dst_port,
                  self.length,
                  self.checksum)

        return repacked_bytes