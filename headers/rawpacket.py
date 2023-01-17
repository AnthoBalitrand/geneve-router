from ipv4 import IPv4

class RawPacket:
    def __init__(self, raw_geneve_packet):
        self.raw_data = raw_geneve_packet
        self.outer_ipv4_header = IPv4(self)
