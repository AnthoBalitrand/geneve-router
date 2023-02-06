from struct import unpack, pack_into


class TCP:
    """
    TCP header representation

    |1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|1 2 3 4 5 6 7 8|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Source port:    The source port of the TCP segment
    Dest. port:     The destination port of the TCP segment
    Seq. number:    The TCP sequence number
    Ack. number:    The TCP ack number (seq number of the next expected segment)
    Data offset:    The number of 32 bits words (multiples of 4 bytes) composing the TCP header = where the data begins
    Reserved:       Has to be 0
    Control bits:   URG:  Urgent Pointer field significant
                    ACK:  Acknowledgment field significant
                    PSH:  Push Function
                    RST:  Reset the connection
                    SYN:  Synchronize sequence numbers
                    FIN:  No more data from sender
    Window:         The TCP window value (the number of bytes the sender is willing to accept)
    Checksum:       Calculated from part of the IP header, TCP header + payload to ensure integrity
    Urgent Pointer:
    Options:        Multiple options can be added (variable length) the the header
    Padding:        "0"s placed at the end of the header to ensure its length is a multiple of 32 bits words (4 bytes)
    """

    def __init__(self, rawpacket, start_padding=0, ip_payload_length=0):
        # extracting bytes up to the options field (20 bytes)
        # we need first to find the total length of the header (data offset) to know
        # the size of the options + padding
        unpacked_struct = unpack('!HH4s4sHHHH', rawpacket.raw_data[start_padding:start_padding + 20])

        self.src_port = unpacked_struct[0]
        self.dst_port = unpacked_struct[1]
        self.seq_num = unpacked_struct[2]
        self.ack_num = unpacked_struct[3]

        self.data_offset = unpacked_struct[4] >> 12
        self.urg = unpacked_struct[4] >> 5 & 0x1
        self.ack = unpacked_struct[4] >> 4 & 0x1
        self.psh = unpacked_struct[4] >> 3 & 0x1
        self.rst = unpacked_struct[4] >> 2 & 0x1
        self.syn = unpacked_struct[4] >> 1 & 0x1
        self.fin = unpacked_struct[4] & 0x1

        self.window = unpacked_struct[5]

        self.checksum = unpacked_struct[6]

        self.urg_pointer = unpacked_struct[7]

        if self.data_offset > 5:
            self.options_raw = rawpacket.raw_data[start_padding + 20:start_padding + 20 + (self.data_offset - 5) * 4]

        self.payload_length = ip_payload_length - (self.data_offset * 32)

    @property
    def tcp_flags_str(self):
        flags = ""
        flags += "S" if self.syn else ""
        flags += "A" if self.ack else ""
        flags += "R" if self.rst else ""
        flags += "F" if self.fin else ""
        flags += "U" if self.urg else ""
        flags += "P" if self.psh else ""
        return flags