from headers import ipv4, udp, geneve
import config

class UnmatchedGenevePort(Exception):
    "raised when the UDP destination port is not matching config.GENEVE_PORT"
    pass

class RawPacket:
    def __init__(self, logger, raw_geneve_packet):
        self.raw_data = raw_geneve_packet
        self.outter_ipv4 = ipv4.IPv4(self)
        self.outter_udp = udp.UDP(self, self.outter_ipv4.header_length_bytes)
        if not self.outter_udp.dst_port == config.GENEVE_PORT:
            raise UnmatchedGenevePort
        else:
            logger.debug(f"GENEVE - Received packet on port {config.GENEVE_PORT} !")
        self.geneve = geneve.Geneve(self, self.outter_ipv4.header_length_bytes + 8)
