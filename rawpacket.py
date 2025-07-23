from headers import ipv4, icmp, tcp, udp, geneve
import config
import ipaddress


class UnmatchedGenevePort(Exception):
    "raised when the UDP destination port is not matching config.GENEVE_PORT"
    pass


class RawPacket:
    def __init__(self, logger, raw_geneve_packet, flow_tracker, udp_only):
        self.logger = logger
        self.udp_only = udp_only
        self.raw_data = raw_geneve_packet

        # if the data is coming from a raw socket (which should be the case), let's unpack the outter IP/UDP headers
        if not udp_only:
            self.outter_ipv4 = ipv4.IPv4(self.raw_data)
            self.outter_udp = udp.UDP(self.raw_data, self.outter_ipv4.header_end_byte)
            if not self.outter_udp.dst_port == config.GENEVE_PORT:
                raise UnmatchedGenevePort
            #self.logger.debug(f"pre-processing outter_ipv4 : {self.outter_ipv4}")
            #self.logger.debug(f"pre-processing outter_udp : {self.outter_udp}")

        self.geneve = geneve.Geneve(self.raw_data, 0 if udp_only else self.outter_ipv4.header_length_bytes + 8)
        #self.logger.debug(f"pre-processing geneve : {self.geneve}")

        self.inner_ipv4 = ipv4.IPv4(self.raw_data, self.geneve.header_end_byte)
        #self.logger.debug(f"pre-precessing inner_ipv4 : {self.inner_ipv4}")

        if self.inner_ipv4.protocol == 17:
            self.inner_l4 = udp.UDP(self.raw_data, self.inner_ipv4.header_end_byte, self.inner_ipv4.payload_length)
            #self.logger.debug(f"pre-processing inner_l4 : {self.inner_l4}")
            if self.inner_l4.dst_port in [500, 4500]:
                self.logger.debug(raw_geneve_packet.hex())
                self.logger.debug(f"pre-processing geneve : {self.geneve}")
                self.logger.debug(f"pre-precessing inner_ipv4 : {self.inner_ipv4}")
                self.logger.debug(f"pre-processing inner_l4 : {self.inner_l4}")
                self.inner_l4.swap_ports()
                self.inner_ipv4.swap_addresses()
                self.logger.debug(self.raw_data[self.inner_l4.header_end_byte::])
                if self.raw_data[self.inner_l4.header_end_byte::].decode('utf-8').strip() == "ping":
                    self.raw_data = bytearray(self.raw_data)
                    self.raw_data = self.raw_data[:-5]
                    extension_info = bytearray()
                    extension_info.extend("pong from ".encode('utf-8'))
                    extension_info.extend(str(ipaddress.IPv4Address(self.inner_l4.src_addr)).encode('utf-8'))
                    extension_info.extend("\n".encode('utf-8'))
                    extension_length = len(extension_info) - 4
                    logger.debug(f"extension_info : {extension_info} / extension_length : {extension_length}")
                    self.raw_data.extend(extension_info)
                    self.raw_data = bytes(self.raw_data)
                    self.inner_l4.length += extension_length
                    self.inner_ipv4.total_length += extension_length
                    self.outter_udp.length += extension_length
                    self.outter_ipv4.total_length += extension_length
        elif self.inner_ipv4.protocol == 6:
            self.inner_l4 = tcp.TCP(self.raw_data, self.inner_ipv4.header_end_byte, self.inner_ipv4.payload_length)
            #self.logger.debug(f"pre-processing inner_l4 : {self.inner_l4}")
        elif self.inner_ipv4.protocol == 1:
            self.inner_l4 = icmp.ICMP(self.raw_data, self.inner_ipv4.header_end_byte, self.inner_ipv4.payload_length)
            #self.logger.debug(f"pre-processing inner_l4 : {self.inner_l4}")
        else:
            self.logger.error(f"GENEVE - Unknown inner packet type ({self.inner_ipv4.protocol})")
            self.inner_l4 = None

        if not self.udp_only:
            self.logger.debug(f"GENEVE - {self.outter_ipv4} {self.outter_udp} {self.geneve} {self.inner_ipv4} {self.inner_l4}")
        else:
            self.logger.debug(
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
        if not self.udp_only:
            if self.inner_l4.src_port in [500, 4500]:
                self.logger.debug(f"post-processing outter_ipv4 : {self.outter_ipv4}")
                self.logger.debug(f"post-processing outter_udp : {self.outter_udp}")
                self.logger.debug(f"post-processing geneve : {self.geneve}")
                self.logger.debug(f"post-processing inner_ipv4 : {self.inner_ipv4}")
                self.logger.debug(f"post-processing inner_l4 : {self.inner_l4}")
                ret = b''.join([
                self.outter_ipv4.repack(), 
                self.outter_udp.repack(),
                self.geneve.repack(),
                self.inner_ipv4.repack(),
                self.inner_l4.repack(),
                self.raw_data[self.inner_l4.header_end_byte::]
                ])
                self.logger.debug(ret.hex())
                return ret
            return b''.join([
                self.outter_ipv4.repack(), 
                self.outter_udp.repack(),
                self.geneve.repack(),
                self.inner_ipv4.repack(),
                self.inner_l4.repack(),
                self.raw_data[self.inner_l4.header_end_byte::]
                ])
        # else (if it comes from a bind UDP socket), let's just send back the full raw data untouched
        #self.logger.debug(f"post-processing geneve : {self.geneve}")
        #self.logger.debug(f"post-processing inner_ipv4 : {self.inner_ipv4}")
        #self.logger.debug(f"post-processing inner_l4 : {self.inner_l4}")
        return b''.join([
            self.geneve.repack(),
            self.inner_ipv4.repack(),
            self.inner_l4.repack(),
            self.raw_data[self.inner_l4.header_end_byte::]
            ])
