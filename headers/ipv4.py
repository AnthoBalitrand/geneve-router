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

    Version:        Has to be 4
    IHL:            Internet Header Length is the total length of the header (including options fields) in words count
                    (multiple of 4 bytes)
    DSCP:           Differentiated Services Code Point is used for QoS classification and marking
    ECN:            Explicit Congestion Notification is used to signal and reduce congestion between compatible hosts
    Total Length:   The size (in bytes) of the full IP packet (header + payload)
    Identification: Used for reassembly of fragmented packets
    Flags :         x = reserved (evil bit)
                    D = Do Not Fragment
                    M = More fragments follow
    Frag. offset:   Used when packet has been fragmented. Measured in 8 bytes (2 words) increments, it indicates the
                    padding of the current fragment from the beginning of the IP datagram.
                    (First fragment has a fragment offset value of 0. Fragments Total Length is multiple of 8 bytes)
    TTL:            Decremented by each router to avoid infinite forwarding of the packet in routing loops
    Protocol:       Indicates which protocol is transported on the payload
    Head. checksum: Ensures integrity of the IP header
    Src address:    Source IP address of the packet
    Dst address:    Destination IP address of the packet
    Options:        Multiple options can be added (variable length) the the header
    Padding:        "0"s placed at the end of the header to ensure its length is a multiple of 32 bits words (4 bytes)
    """

    def __init__(self, rawpacket, start_padding=0, parse_options=True):
        # extracting bytes up to the options field
        # we need first to find the total length of the header (IHL) to know
        # the size of the options + padding
        unpacked_struct = unpack('!BBHHHBBH4s4s', rawpacket.raw_data[start_padding:start_padding + 20])

        self.version = unpacked_struct[0] >> 4
        if self.version != 4:
            raise ValueError(f"IPv4 header contains unsupported version : {self.version}")

        self.ihl = unpacked_struct[0] & 0xF
        self.header_length_bytes = self.ihl * 4
        self.dscp = unpacked_struct[1] >> 2
        self.ecn = unpacked_struct[1] & 0x3
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
        # substracting it to the IHL field permits to calculate the number of options words
        self.options_words_count = self.ihl - 5
        if self.options_words_count:
            # if there are options on the header, we extract it from the raw bytes of the received packet
            self.options_raw = rawpacket.raw_data[start_padding + 20:start_padding + 20 + self.options_words_count * 4]

        self.payload_length = self.total_length - (self.ihl * 32)

    def swap_addresses(self):
        """
        Swaps the source and destination IP addresses values
        :return:
        """
        self.src_addr, self.dst_addr = self.dst_addr, self.src_addr

    def repack(self, null_checksum=False):
        """
        Rebuilds a byte-encoded IP header
        :return: (bytearray) Byte-encoded packed IP header
        """

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
                  0 if null_checksum else self.checksum,
                  self.src_addr,
                  self.dst_addr)

        # adding options if there was any in the initial header
        if self.options_count:
            repacked_bytes.append(self.options_raw)

        # returns the built new header
        return repacked_bytes

    @property
    def src_addr_str(self):
        """
        Property, returns the string version of the source IP address
        :return: (str) Header source IP address value
        """
        return '.'.join(str(c) for c in self.src_addr)

    @property
    def dst_addr_str(self):
        """
        Property, returns the string version of the destination IP address
        :return: (str) Header destination IP address value
        """
        return '.'.join(str(c) for c in self.dst_addr)

    def __repr__(self):
        """
        Returns the string representation of the IPv4 object (header)
        :return: (str) String representation of the current IPv4 object instance
        """
        return f"IPv4 header. Version {self.version}. Source IP {self.src_addr_str}. Destination IP {self.dst_addr_str}"

    def update_checksum(self):
        self.checksum = IPv4.calculate_checksum_for_bytes(self.repack())

    @classmethod
    def calculate_checksum_for_bytes(cls, header_bytes: bytes) -> int:
        """Calculate the checksum for the provided header."""

        def carry_around_add(a, b):
            c = a + b
            return (c & 0xffff) + (c >> 16)

        s = 0
        for i in range(0, len(header_bytes), 2):
            w = header_bytes[i + 1] + (header_bytes[i] << 8)
            s = carry_around_add(s, w)
        return ~s & 0xffff