import dpkt
import struct
import pandas as pd

SENDER = '172.24.19.53'
RECEIVER = '20.231.4.48'

pd.options.display.float_format = "{:,.6f}".format


class Packet:
    def __init__(self, data, timestamp):

        # initialize the structure of the packet
        self.data = data
        self.timestamp = timestamp
        self.source_ip_address = ''
        self.destination_ip_address = ''
        self.source_port = 0
        self.destination_port = 0
        self.length = 0
        self.protocol = ''
        self.sequence_number = 0
        self.acknowledge_number = 0
        self.window_size = 0
        self.mss = 0
        self.flag = ''
        self.additional = ''
        self.size = len(data)
        self.flag_syn = False
        self.flag_ack = False
        self.flag_fin = False

    def parse(self):
        self.set_source_ip_address()
        self.set_destination_ip_address()
        self.set_source_port()
        self.set_destination_port()
        self.set_length()
        self.set_protocol()

        if self.protocol == 'TCP':
            self.set_sequence_number()
            self.set_acknowledge_number()
            self.set_window_size()
            self.set_max_segment_size()
            self.set_flag()
            self.set_flags()

    def print_packet_information(self, ctr):

        # print("\n")
        print("------------------------------------------------------------------------------------------------")
        print("Packet " + str(ctr) + ": ")
        print("------------------------------------------------------------------------------------------------")
        print("Timestamp: ", self.timestamp)
        print("Source Ip address: ", self.source_ip_address)
        print("Destination Ip address: ", self.destination_ip_address)
        print("Source Port: ", self.source_port)
        print("Destination Port: ", self.destination_port)
        print("Length: ", self.length)
        print("Protocol: ", self.protocol)

        if self.protocol == 'TCP':
            print("Sequence number: ", self.sequence_number)
            print("Acknowledge number: ", self.acknowledge_number)
            print("Window Size: ", self.window_size)
            print("Maximum Segment Size (MSS): ", self.mss)
            print("Flags: ", self.flag)
            print("SYN Flag: ", self.flag_syn)
            print("ACK Flag: ", self.flag_ack)
            print("FIN Flag: ", self.flag_fin)

    def unpack_info(self, start_index, last_index, _format=">B", _str=True):
        """ unpacks the binary data in the specified format """

        info = struct.unpack(_format, self.data[start_index:last_index])[0]
        if _str:
            info = str(info)
        return info

    def set_source_ip_address(self):
        self.source_ip_address += self.unpack_info(26, 27)
        self.source_ip_address += "." + self.unpack_info(27, 28)
        self.source_ip_address += "." + self.unpack_info(28, 29)
        self.source_ip_address += "." + self.unpack_info(29, 30)

    def set_destination_ip_address(self):
        self.destination_ip_address += self.unpack_info(30, 31)
        self.destination_ip_address += "." + self.unpack_info(31, 32)
        self.destination_ip_address += "." + self.unpack_info(32, 33)
        self.destination_ip_address += "." + self.unpack_info(33, 34)

    def set_source_port(self):
        self.source_port = int(self.unpack_info(34, 36, _format=">H"))

    def set_destination_port(self):
        self.destination_port = int(self.unpack_info(36, 38, _format=">H"))

    def set_length(self):
        self.length = self.size

    def set_protocol(self):
        protocol_value = int(self.unpack_info(23, 24))

        if protocol_value == 17:
            self.protocol = 'UDP'
        elif protocol_value == 6:
            self.protocol = 'TCP'

    def set_sequence_number(self):
        self.sequence_number = self.unpack_info(38, 42, _format=">I")

    def set_acknowledge_number(self):
        self.acknowledge_number = self.unpack_info(42, 46, _format=">I")

    def set_window_size(self):
        self.window_size = self.unpack_info(48, 50, _format=">H")

    def set_max_segment_size(self):
        try:
            self.mss = self.unpack_info(56, 58, _format=">H")
        except:
            self.mss = 0

    def set_flag(self):
        self.flag = bin(self.unpack_info(46, 48, _format=">H", _str=False))[2:]

    def set_flags(self):
        self.flag_ack = (int(self.flag) & 16 != 0)
        self.flag_syn = (int(self.flag) & 2 != 0)
        self.flag_fin = (int(self.flag) & 1 != 0)


def process_one_packet(packet, timestamp):
    pkt = Packet(packet, timestamp)
    pkt.parse()
    return pkt


def process_packets(packets, csv_file_name, src_ip, dst_ip, src_port, dst_port):
    total_number_of_packets = 0
    number_of_udp_packets = 0
    number_of_tcp_packets = 0
    number_of_flashes_detected = 0

    count = 1356

    packets_list = []

    for timestamp, packet_data in packets:
        pkt = process_one_packet(packet_data, timestamp)

        total_number_of_packets += 1
        if pkt.protocol == 'UDP':
            number_of_udp_packets += 1
        elif pkt.protocol == 'TCP':
            number_of_tcp_packets += 1

        flag = 0

        if pkt.source_ip_address == src_ip and pkt.destination_ip_address == dst_ip and \
                pkt.source_port == src_port and pkt.destination_port == dst_port:

            if 405 <= pkt.size <= 870 and pkt.protocol == 'UDP':
                number_of_flashes_detected += 1
                flag = 1

            packet_info = [pkt.timestamp,
                           pkt.source_ip_address,
                           pkt.destination_ip_address,
                           pkt.source_port,
                           pkt.destination_port,
                           pkt.length,
                           pkt.protocol,
                           flag]

            packets_list.append(packet_info)

        count += 1

    columns_list = ['Timestamp', 'SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort',
                    'Length', 'Protocol', 'isFlash']

    df = pd.DataFrame(packets_list, columns=columns_list)
    print(df)
    df.to_csv(csv_file_name)

    print("Total number of packets: ", total_number_of_packets)
    print("Number of UDP packets: ", number_of_udp_packets)
    print("Number of TCP packets: ", number_of_tcp_packets)
    print("Number of flashes detected: ", number_of_flashes_detected)

    return df


if __name__ == '__main__':
    # captured pcap file path
    pcap_file_name_sender = '/Users/tejaswini/Desktop/fcn_project/teams_zoom/zoom_delay_20_same_network_sender.pcap'
    pcap_file_name_receiver = '/Users/tejaswini/Desktop/fcn_project/teams_zoom/zoom_20_delay_same_network_receiver.pcap'

    # add timestamp column in the given csv
    csv_file1 = '/Users/tejaswini/Desktop/fcn_project/teams_zoom/zoom_20_same_network_sender.csv'
    csv_file2 = '/Users/tejaswini/Desktop/fcn_project/teams_zoom/zoom_20_same_network_receiver.csv'

    SENDER_IP = '172.24.19.53'
    RECEIVER_IP = '173.231.80.73'

    SENDER_PORT = 51537
    RECEIVER_PORT = 8801

    # open the pcap file
    with open(pcap_file_name_sender, 'rb') as pcap_file1:
        pcap1 = dpkt.pcap.Reader(pcap_file1)
        df1 = process_packets(pcap1, csv_file1, SENDER_IP, RECEIVER_IP, SENDER_PORT, RECEIVER_PORT)

    SENDER_IP_REC = '173.231.80.73'
    RECEIVER_IP_REC = '172.24.24.185'

    SENDER_PORT_REC = 8801
    RECEIVER_PORT_REC = 61547

    # open the pcap file
    with open(pcap_file_name_receiver, 'rb') as pcap_file2:
        pcap2 = dpkt.pcap.Reader(pcap_file2)
        df2 = process_packets(pcap2, csv_file2, SENDER_IP_REC, RECEIVER_IP_REC, SENDER_PORT_REC, RECEIVER_PORT_REC)





