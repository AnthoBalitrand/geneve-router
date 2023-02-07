from headers import ipv4, icmp, tcp, udp, geneve
import config


class UnmatchedGenevePort(Exception):
    "raised when the UDP destination port is not matching config.GENEVE_PORT"
    pass


class RawPacket:
    def __init__(self, logger, raw_geneve_packet, flow_tracker):
        self.raw_data = raw_geneve_packet
        self.outter_ipv4 = ipv4.IPv4(self)
        self.outter_udp = udp.UDP(self, self.outter_ipv4.header_length_bytes)
        if not self.outter_udp.dst_port == config.GENEVE_PORT:
            raise UnmatchedGenevePort
        self.geneve = geneve.Geneve(self, self.outter_ipv4.header_length_bytes + 8)
        logger.debug(f"GENEVE - AWS Flow Cookie option value : {self.geneve.flow_cookie}")
        self.inner_ipv4 = ipv4.IPv4(self, self.outter_ipv4.header_length_bytes + 8 + self.geneve.header_length_bytes)
        logger.debug(f"GENEVE - Inner packet info : src_ip = {self.inner_ipv4.src_addr_str} / dst_ip = {self.inner_ipv4.dst_addr_str} / proto = {self.inner_ipv4.protocol}")
        if self.inner_ipv4.protocol == 17:
            self.inner_l4 = udp.UDP(self, self.outter_ipv4.header_length_bytes + 8 + self.geneve.header_length_bytes + self.inner_ipv4.header_length_bytes, self.inner_ipv4.payload_length)
            logger.debug(f"GENEVE - Inner packet info : UDP src_port : {self.inner_l4.src_port} / dst_port : {self.inner_l4.dst_port}")
        elif self.inner_ipv4.protocol == 6:
            self.inner_l4 = tcp.TCP(self, self.outter_ipv4.header_length_bytes + 8 + self.geneve.header_length_bytes + self.inner_ipv4.header_length_bytes, self.inner_ipv4.payload_length)
            logger.debug(f"GENEVE - Inner packet info : TCP src_port : {self.inner_l4.src_port} / dst_port : {self.inner_l4.dst_port} / flags : {self.inner_l4.tcp_flags_str}")
        elif self.inner_ipv4.protocol == 1:
            self.inner_l4 = icmp.ICMP(self, self.outter_ipv4.header_length_bytes + 8 + self.geneve.header_length_bytes + self.inner_ipv4.header_length_bytes), self.inner_ipv4.payload_length
            logger.debug(f"GENEVE - Inner packet info : ICMP type : {self.inner_l4.type} / code : {self.inner_l4.code}")
        else:
            logger.debug(f"GENEVE - Unknown inner packet type")

        if flow_tracker and self.inner_ipv4.protocol in [1, 6, 17]:
            flow_tracker.update_flow(self)

        self.outter_ipv4.swap_addresses()
        self.outter_ipv4.ttl -= 1
        # Disabled update_checksum to check if NIC offload does it by itself
        # self.outter_ipv4.update_checksum()

    @property
    def resp(self):
        return b''.join([
            self.outter_ipv4.repack(),
            self.raw_data[self.outter_ipv4.header_length_bytes::]
        ])
