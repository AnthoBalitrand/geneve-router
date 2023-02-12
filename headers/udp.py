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

    Source port:    The source port of the UDP datagram
    Dest. port:     The destination port of the UDP datagram
    Length:         The length (in bytes) of the UDP payload (including header size, which is always 8)
    Checksum:       Calculated from part of the IP header, UDP header + payload to ensure integrity
    """

    def __init__(self, rawpacket, start_padding=0, ip_payload_length=0):
        unpacked_struct = unpack('!HHHH', rawpacket.raw_data[start_padding:start_padding + 8])

        self.src_port = unpacked_struct[0]
        self.dst_port = unpacked_struct[1]

        self.length = unpacked_struct[2]
        self.checksum = unpacked_struct[3]

        self.payload_length = ip_payload_length - 8

    def swap_ports(self):
        """
        Swaps the source and destination ports values
        :return:
        """
        self.src_port, self.dst_port = self.dst_port, self.src_port

    def repack(self):
        """
        Rebuilds a byte-encoded UDP header
        :return: (bytearray) Byte-encoded packed UDP header
        """
        repacked_bytes = bytearray(8)

        pack_into('!HHHH', repacked_bytes, 0,
                  self.src_port,
                  self.dst_port,
                  self.length,
                  self.checksum)

        return repacked_bytes

    def __repr__(self):
        """
        Returns the string representation of the UDP object (header)
        :return: (str) String representation of the current UDP object instance
        """
        return f"[UDP   SRC port:{self.src_port} DST port:{self.dst_port} Length:{self.length}  ]"