import datetime
import math


class Flow:
    def __init__(self, logger, flow_packet):
        self.aws_flow_cookie = flow_packet.geneve.flow_cookie
        self.logger = logger
        self.state = None
        self.protocol = flow_packet.inner_ipv4.protocol
        self.src_addr = flow_packet.inner_ipv4.src_addr_str
        self.dst_addr = flow_packet.inner_ipv4.dst_addr_str
        if self.protocol in [6, 17]:
            self.src_port = flow_packet.inner_l4.src_port
            self.dst_port = flow_packet.inner_l4.dst_port
            if self.protocol == 6:
                if flow_packet.inner_l4.syn and not flow_packet.inner_l4.ack:
                    self.state = 'SYN'
                else:
                    self.logger.error("FLOW-TRACKER - First packet for un-initialized TCP flow is not a SYN !")
            else:
                self.state = 'RUN'
        else:
            self.state = 'RUN'
            self.src_port = 0
            self.dst_port = 0
        self.start_timestamp = math.floor(datetime.datetime.utcnow().timestamp())
        self.lastpacket_timestamp = self.start_timestamp
        self.pkts_sent = 1
        self.pkts_received = 0
        self.bytes_sent = flow_packet.inner_l4.payload_length
        self.bytes_received = 0
        self.logger.debug(f"FLOW-TRACKER - New flow added (AWS flow cookie : {self.aws_flow_cookie})")

    def update_flow(self, flow_packet):
        if flow_packet.inner_ipv4.dst_addr_str == self.dst_addr:
            self.pkts_sent += 1
            self.bytes_sent += flow_packet.inner_l4.payload_length
        elif flow_packet.inner_ipv4.dst_addr_str == self.src_addr:
            self.pkts_received += 1
            self.bytes_received += flow_packet.inner_l4.payload_length
        else:
            self.logger.error(
                f"FLOW-TRACKER - Error matching flow while trying to update statistics for flow cookie {flow_packet.geneve.flow_cookie}")
            return 0

        if self.protocol == 6:
            if self.state == 'FINACK':
                if flow_packet.inner_l4.ack and not flow_packet.inner_l4.syn:
                    self.state = 'CLOSED'
                    self.logger.debug(f"FLOW-TRACKER - Flow {flow_packet.geneve.flow_cookie} TCP moved to CLOSED state")
            elif self.state == 'FIN':
                if flow_packet.inner_l4.fin and flow_packet.inner_l4.ack:
                    self.state = 'FINACK'
            elif self.state == 'RUN':
                if flow_packet.inner_l4.fin:
                    self.state = 'FIN'
            elif self.state == 'SYNACK':
                if flow_packet.inner_l4.ack and not flow_packet.inner_l4.syn and not flow_packet.inner_l4.rst:
                    self.state = 'RUN'
                    self.logger.debug(f"FLOW-TRACKER - Flow {flow_packet.geneve.flow_cookie} TCP moved to RUN state")
            elif self.state == 'SYN':
                if flow_packet.inner_l4.syn and flow_packet.inner_l4.ack:
                    self.state = 'SYNACK'
        self.lastpacket_timestamp = math.floor(datetime.datetime.utcnow().timestamp())
        self.logger.debug(f"FLOW-TRACKER - Updated flow statistics for flow cookie {flow_packet.geneve.flow_cookie}")

    def __repr__(self):
        return f"Flow {self.aws_flow_cookie} - IP {self.protocol} - SRC {self.src_addr}:{self.src_port} - DST {self.dst_addr}:{self.dst_port} - " \
               f"Pkts/bytes sent {self.pkts_sent}/{self.bytes_sent} - Pkts/bytes received {self.pkts_received}/{self.bytes_received} - State {self.state}"


class FlowTracker:
    def __init__(self, logger):
        self.tracked_flows = dict()
        self.logger = logger
        self.logger.info("FlowTracker initialized")

    def update_flow(self, flow_packet):
        if flow_packet.geneve.flow_cookie not in self.tracked_flows:
            self.tracked_flows[flow_packet.geneve.flow_cookie] = Flow(self.logger, flow_packet)
        else:
            self.tracked_flows.get(flow_packet.geneve.flow_cookie).update_flow(flow_packet)
