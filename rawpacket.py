from headers import ipv4, icmp, tcp, udp, geneve
import config


class UnmatchedGenevePort(Exception):
    "raised when the UDP destination port is not matching config.GENEVE_PORT"
    pass


class RawPacket:
    def __init__(self, logger, raw_geneve_packet, flow_tracker, udp_only):
        self.udp_only = udp_only
        self.raw_data = raw_geneve_packet

        # if the data is coming from a raw socket (which should be the case), let's unpack the outter IP/UDP headers
        if not udp_only:
            self.outter_ipv4 = ipv4.IPv4(self.raw_data)
            self.outter_udp = udp.UDP(self.raw_data, self.outter_ipv4.header_end_byte)
            if not self.outter_udp.dst_port == config.GENEVE_PORT:
                raise UnmatchedGenevePort

        self.geneve = geneve.Geneve(self.raw_data, 0 if udp_only else self.outter_ipv4.header_length_bytes + 8)
        self.inner_ipv4 = ipv4.IPv4(self.raw_data, self.geneve.header_end_byte)
        if self.inner_ipv4.protocol == 17:
            self.inner_l4 = udp.UDP(self.raw_data, self.inner_ipv4.header_end_byte, self.inner_ipv4.payload_length)
        elif self.inner_ipv4.protocol == 6:
            self.inner_l4 = tcp.TCP(self.raw_data, self.inner_ipv4.header_end_byte, self.inner_ipv4.payload_length)
        elif self.inner_ipv4.protocol == 1:
            self.inner_l4 = icmp.ICMP(self.raw_data, self.inner_ipv4.header_end_byte, self.inner_ipv4.payload_length)
        else:
            logger.error(f"GENEVE - Unknown inner packet type ({self.inner_ipv4.protocol})")
            self.inner_l4 = None

        if not self.udp_only:
            logger.debug(f"GENEVE - {self.outter_ipv4} {self.outter_udp} {self.geneve} {self.inner_ipv4} {self.inner_l4}")
        else:
            logger.debug(
                f"GENEVE - {self.geneve} {self.inner_ipv4} {self.inner_l4}")

        if flow_tracker and self.inner_ipv4.protocol in [1, 6, 17]:
            flow_tracker.update_flow(self)

        # if raw data comes from the raw socket, we need to swap the IP addresses and decrease the TTL as the kernel
        # will not do that for us
        if not udp_only:
            self.outter_ipv4.swap_addresses()
            self.outter_ipv4.ttl -= 1

    @property
    def resp(self):
        # if we need to send back the data to a raw buffer, send back the repacked (updated) IP header, and then
        # the rest of the raw data untouched
        if self.udp_only:
            return b''.join([
                self.outter_ipv4.repack(),
                self.raw_data[self.outter_ipv4.header_length_bytes::]
            ])
        # else (if it comes from a bind UDP socket), let's just send back the full raw data untouched
        return self.raw_data
