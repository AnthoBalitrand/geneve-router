from struct import unpack, pack_into

class CriticalUnparsedGeneveHeader(Exception):
    "raised when Geneve options parsing is disabled and the endpoint receives a Geneve header with the Critical bit set"
    pass

class Geneve:
    """
    Geneve header representation

    |1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Virtual Network Identifier (VNI)       |    Reserved   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    ~                    Variable-Length Options                    ~
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Source port:    The source port of the UDP datagram
    Version:        Has to be 0, or packet must be dropped (or treated as UDP packet with unknown payload)
    Options length: The length (in 32 bits words count) of the options part of the header
    O (control):    Indicates a Control packet which should not be forwarded by the tunnel endpoints
    C (critical):   Indicates that the header contains critical options which should be parsed. If the tunnel endpoint
                    does not supports options parsing, it must drop the packet.
    Rsvd:           Must be 0.
    Protocol type:  Represents the type of protocol appearing just after the Geneve header.
    VNI:            Virtual Network Identifier.
    Reserved:       Must be 0.
    """

    def __init__(self, rawpacket, start_padding=0, parse_options=True):
        unpacked_struct = unpack('!BBH3sB', rawpacket.raw_data[start_padding:start_padding + 8])

        self.version = unpacked_struct[0] >> 6
        # The option length fields represent the options size in words count (multiple of 4 bytes)
        # and does not includes the fixed 8-bytes header size
        self.options_length = unpacked_struct[0] & 0x3F
        self.control = unpacked_struct[1] >> 7
        self.critical = unpacked_struct[1] >> 6 & 0x1
        # Rsvd is always 0. Ignored
        self.protocol = unpacked_struct[2]
        self.vni = unpacked_struct[3]
        # Reserved is always 0. Ignored
        self.parsed_options = list()
        self.raw_options = None

        self.header_length_bytes = 8 + self.options_length * 4

        if self.options_length and parse_options:
            parsed_options_length = 0
            while parsed_options_length < self.options_length * 4:
                self.parsed_options.append(GeneveOption(rawpacket, start_padding + 8 + parsed_options_length))
                parsed_options_length += self.parsed_options[-1].total_length
        elif not parse_options and not self.critical:
            self.raw_options = rawpacket.raw_data[start_padding + 8:start_padding + 8 + self.options_length * 4]
        elif not parse_options and self.critical:
            raise CriticalUnparsedGeneveHeader

    def repack(self):
        """
        Rebuilds a byte-encoded Geneve header
        :return: (bytearray) Byte-encoded packed Geneve header
        """
        repacked_bytes = bytearray(8 + self.options_length * 4)

        pack_into('!BBH3sB', repacked_bytes, 0,
                  self.version << 6 + self.options_length,
                  self.control << 7 + self.critical << 6,
                  self.protocol,
                  self.vni, 0)

        for opt in self.parsed_options:
            repacked_bytes.extend(opt.repack())

    def get_tunnel_option(self, option_class, option_type):
        for opt in self.parsed_options:
            if opt.option_class == option_class and opt.option_type == option_type:
                return opt
        return None

    @property
    def flow_cookie(self):
        return self.get_tunnel_option(option_class=0x0108, option_type=3).option_raw.hex()


class GeneveOption:
    """
    Class for Geneve tunnel options.
    Its structure is as follows:
    |1 2 3 4 5 6 7 8|1 2 3 4 5 6 7  8|1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Option Class         |      Type     |R|R|R| Length  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    ~                  Variable-Length Option Data                  ~
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Source port:    The source port of the UDP datagram
    Option Class:   IANA Geneve Option Class identifier (Type namespace)
    Type:           The option type (in the Option Class namespace).
                    The first bit of the Type field indicates if the option is critical.
    R:              Option control flags, not used.
    Length:         Length of the option (in 32 bits words count), excluding the Option header.
    """

    def __init__(self, rawpacket, start_padding=8):
        unpacked_struct = unpack('!HBB', rawpacket.raw_data[start_padding:start_padding + 4])

        # Class 0x0108 = Amazon
        self.option_class = unpacked_struct[0]

        self.option_type = unpacked_struct[1]
        self.critical = unpacked_struct[1] >> 7

        # R bits are reserved and must be 0. Ignored.
        # The length field represents the option length in words count (multiple of 4 bytes)
        # and does not includes the option header
        self.option_length = unpacked_struct[2] & 0x1F
        self.total_length = self.option_length * 4 + 4

        self.option_raw = rawpacket.raw_data[start_padding + 4:start_padding + 4 + self.option_length * 4]

    def repack(self):
        """
        Rebuilds a byte-encoded version of the GeneveOption
        :return: (bytearray) Byte-encoded packed GeneveOption
        """
        repacked_bytes = bytearray(4 + self.option_length * 4)

        pack_into('!HBB', repacked_bytes, 0,
                  self.option_class,
                  self.option_type,
                  self.option_length)

        repacked_bytes.append(self.option_raw)

        return repacked_bytes