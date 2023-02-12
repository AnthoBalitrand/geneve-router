from headers import ipv4, icmp, tcp, udp, geneve
import config


class UnmatchedGenevePort(Exception):
    "raised when the UDP destination port is not matching config.GENEVE_PORT"
    pass


class RawPacket:
    def __init__(self, logger, raw_geneve_packet, flow_tracker):
        try:
            self.raw_data = raw_geneve_packet
            self.outter_ipv4 = ipv4.IPv4(self)
            self.outter_udp = udp.UDP(self, self.outter_ipv4.header_end_byte)
            if not self.outter_udp.dst_port == config.GENEVE_PORT:
                raise UnmatchedGenevePort
            self.geneve = geneve.Geneve(self, self.outter_ipv4.header_length_bytes + 8)
            #logger.debug(f"GENEVE - AWS Flow Cookie option value : {self.geneve.flow_cookie}")
            self.inner_ipv4 = ipv4.IPv4(self, self.geneve.header_end_byte)
            #logger.debug(f"GENEVE - Inner packet info : src_ip = {self.inner_ipv4.src_addr_str} / dst_ip = {self.inner_ipv4.dst_addr_str} / proto = {self.inner_ipv4.protocol}")
            if self.inner_ipv4.protocol == 17:
                self.inner_l4 = udp.UDP(self, self.inner_ipv4.header_end_byte, self.inner_ipv4.payload_length)
                #logger.debug(f"GENEVE - Inner packet info : UDP src_port : {self.inner_l4.src_port} / dst_port : {self.inner_l4.dst_port}")
            elif self.inner_ipv4.protocol == 6:
                self.inner_l4 = tcp.TCP(self, self.inner_ipv4.header_end_byte, self.inner_ipv4.payload_length)
                #logger.debug(f"GENEVE - Inner packet info : TCP src_port : {self.inner_l4.src_port} / dst_port : {self.inner_l4.dst_port} / flags : {self.inner_l4.tcp_flags_str}")
            elif self.inner_ipv4.protocol == 1:
                self.inner_l4 = icmp.ICMP(self, self.inner_ipv4.header_end_byte, self.inner_ipv4.payload_length)
                #logger.debug(f"GENEVE - Inner packet info : ICMP type : {self.inner_l4.type} / code : {self.inner_l4.code}")
            else:
                logger.error(f"GENEVE - Unknown inner packet type ({self.inner_ipv4.protocol})")
                self.inner_l4 = None

            logger.debug(f"GENEVE - {self.outter_ipv4} {self.outter_udp} {self.geneve} {self.inner_ipv4} {self.inner_l4}")

            if flow_tracker and self.inner_ipv4.protocol in [1, 6, 17]:
                flow_tracker.update_flow(self)

            # swap outter IPv4 header addresses (not outter UDP header ports)
            # plus decrement TTL value
            self.outter_ipv4.swap_addresses()
            self.outter_ipv4.ttl -= 1
        except Exception as e:
            logger.error(f"Unexpected error while parsing received packet : {e}")

    @property
    def resp(self):
        return b''.join([
            self.outter_ipv4.repack(),
            self.raw_data[self.outter_ipv4.header_length_bytes::]
        ])
