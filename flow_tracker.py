import datetime
import math

class FlowTracker:
    def __init__(self, logger):
        self.tracked_flows = dict()
        self.logger = logger
        self.logger.info("FlowTracker initialized")

    def gen_initial_flow_info(self, flow_packet):
        flow_info = dict()
        flow_info['state'] = None
        flow_info['protocol'] = flow_packet.inner_ipv4.protocol
        flow_info['src_addr'] = flow_packet.inner_ipv4.src_addr_str
        flow_info['dst_addr'] = flow_packet.inner_ipv4.dst_addr_str
        if flow_info['protocol'] in [6, 17]:
            flow_info['src_port'] = flow_packet.inner_l4.src_port
            flow_info['dst_port'] = flow_packet.inner_l4.dst_port
            if flow_info['protocol'] == 6:
                if flow_packet.inner_l4.syn and not flow_packet.inner_l4.ack:
                    flow_info['state'] = 'SYN'
                else:
                    self.logger.error("FLOW-TRACKER - First packet for un-initialized flow is not a SYN !")
        flow_info['start_timestamp'] = math.floor(datetime.datetime.utcnow().timestamp())
        flow_info['lastpacket_timestamp'] = flow_info['start_timestamp']
        flow_info['pkts_sent'] = 1
        flow_info['pkts_received'] = 0
        flow_info['bytes_sent'] = flow_packet.inner_l4.payload_length
        flow_info['bytes_received'] = 0

        return flow_info

    def update_flow_info(self, flow_packet):
        if updating_flow := self.tracked_flows.get(flow_packet.geneve.flow_cookie):
            if flow_packet.inner_ipv4.dst_addr_str == updating_flow['dst_addr']:
                updating_flow['pkts_sent'] += 1
                updating_flow['bytes_sent'] += flow_packet.inner_l4.payload_length
            elif flow_packet.inner_ipv4.dst_addr_str == updating_flow['src_addr']:
                updating_flow['pkts_received'] += 1
                updating_flow['bytes_received'] += flow_packet.inner_l4.payload_length
            else:
                self.logger.error(f"FLOW-TRACKER - Error matching flow while trying to update statistics for flow cookie {flow_packet.geneve.flow_cookie}")
                return 0

            if updating_flow['protocol'] == 6:
                if updating_flow['state'] == 'FINACK':
                    if flow_packet.inner_l4.ack and not flow_packet.inner_l4.syn:
                        updating_flow['state'] = 'CLOSED'
                        self.logger.debug(f"FLOW-TRACKER - Flow {flow_packet.geneve.flow_cookie} TCP moved to CLOSED state")
                elif updating_flow['state'] == 'FIN':
                    if flow_packet.inner_l4.fin and flow_packet.inner_l4.ack:
                        updating_flow['state'] = 'FINACK'
                elif updating_flow['state'] == 'RUN':
                    if flow_packet.inner_l4.fin and not flow_packet.inner_l4.ack:
                        updating_flow['state'] = 'FIN'
                elif updating_flow['state'] == 'SYNACK':
                    if flow_packet.inner_l4.ack and not flow_packet.inner_l4.syn and not flow_packet.inner_l4.rst:
                        updating_flow['state'] = 'RUN'
                        self.logger.debug(f"FLOW-TRACKER - Flow {flow_packet.geneve.flow_cookie} TCP moved to RUN state")
                elif updating_flow['state'] == 'SYN':
                    if flow_packet.inner_l4.syn and flow_packet.inner_l4.ack:
                        updating_flow['state'] = 'SYNACK'
            updating_flow['lastpacket_timestamp'] = math.floor(datetime.datetime.utcnow().timestamp())
        else:
            self.logger.error(f"FLOW-TRACKER - Unable to find flow with flow cookie {flow_packet.geneve.flow_cookie}")

    def update_flow(self, flow_packet):
        if not flow_packet.geneve.flow_cookie in self.tracked_flows:
            self.tracked_flows[flow_packet.geneve.flow_cookie] = self.gen_initial_flow_info(flow_packet)
            self.logger.debug(f"FLOW-TRACKER - Added flow {flow_packet.geneve.flow_cookie} to tracker with initial values")
            self.logger.debug(self.tracked_flows[flow_packet.geneve.flow_cookie])
        else:
            self.update_flow_info(flow_packet)
            self.logger.debug(f"FLOW-TRACKER - Update flow statistics for flow cookie {flow_packet.geneve.flow_cookie}")
