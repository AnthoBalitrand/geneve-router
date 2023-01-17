from struct import unpack, pack_into

class IPv4:
    """
    IPv4 header representation

    |1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |    DSCP   |ECN|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    |                               |x D M|                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Flags :
    x = reserved (evil bit)
    D = Do Not Fragment
    M = More fragments follow
    """

    def __init__(self, rawpacket, start_padding=0):
        # extracting bytes up to the options field
        # we need first to find the total length of the header (IHL) to know
        # the size of the options + padding
        unpacked_struct = unpack('!BBHHHBBH4s4s', rawpacket.raw_data[start_padding:])

        # version has to be 4
        self.version = unpacked_struct[0] >> 4
        if self.version != 4:
            raise ValueError(f"IPv4 header contains unsupported version : {self.version}")

        self.ihl = unpacked_struct[0] & 0xF
        self.header_length_bytes = self.ihl * 4
        self.dscp = unpacked_struct[1] >> 2
        self.ecn = unpacked_struct[1] & 0x3
        # note : total length includes the header size
        self.total_length = unpacked_struct[2]

        self.identification = unpacked_struct[3]
        self.x_flag = unpacked_struct[4] >> 15 & 1
        self.dnf = unpacked_struct[4] >> 14 & 1
        self.more_fragments = unpacked_struct[4] >> 13 & 1
        self.fragment_offset = unpacked_struct[4] & 0x2000

        self.ttl = unpacked_struct[5]
        self.protocol = unpacked_struct[6]
        self.checksum = unpacked_struct[7]

        self.src_addr = unpacked_struct[8]
        self.dst_addr = unpacked_struct[9]

        # A basic IPv4 header is composed of 5 32-bits words
        # substracting it to the IHL field permits to calculate the number of
        # options words
        self.options_count = self.ihl - 5
        if self.options_count:
            # if there are options on the header, we extract it from the raw bytes of the received packet
            self.options_raw = rawpacket.raw_data[start_padding + 20:(start_padding + 20 + self.options_count * 4)]

    def swap_addresses(self):
        self.src_addr, self.dst_addr = self.dst_addr, self.src_addr

    def repack(self):
        # initialize an empty byte array matching the current header size
        repacked_bytes = bytearray(self.ihl * 4)

        # packing data to reconstruct the header
        pack_into('!BBHHHBBH4s4s', repacked_bytes, 0,
                  (self.version << 4) + self.ihl,
                  (self.dscp << 2) + self.ecn,
                  self.total_length,
                  self.identification,
                  (self.x_flag << 15) + (self.dnf << 14) + (self.more_fragments << 13) + self.fragment_offset,
                  self.ttl,
                  self.protocol,
                  self.checksum,
                  self.src_addr,
                  self.dst_addr)

        # adding options if there was any in the initial header
        if self.options_count:
            repacked_bytes.append(self.options_raw)

        # returns the built new header
        return repacked_bytes

    @property
    def src_addr_str(self):
        return '.'.join(str(c) for c in self.src_addr)

    @property
    def dst_addr_str(self):
        return '.'.join(str(c) for c in self.dst_addr)

        #mohamed beldi