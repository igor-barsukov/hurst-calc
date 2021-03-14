import dpkt
import socket
import csv
import sys
import getopt
import os

## linux notation
# globalFilePath = 'D:/Aspirantura/traffic/moodle_2020/testfile.2020-06-07.%H.%M.%S.pcap'
## Windows notation
globalFilePath = 'C:\\Users\\igba0714\\Documents\\Studying\\Postgrade\\moodle_2020\\2020-11-16-22-11.pcap\\testfile.2020-11-16.%H.%M.%S.pcap'

class Connection:
    
    def __init__(self, a_addr, a_port, b_addr, b_port):
        self.a_addr = a_addr
        self.a_port = a_port
        self.b_addr = b_addr
        self.b_port = b_port
        self.key = a_addr + '_' + str(a_port) + '_' + b_addr + '_' + str(b_port)        
        self.reversed_key = b_addr + '_' + str(b_port) + '_' + a_addr + '_' + str(a_port)
        self.a_bytes = 0
        self.b_bytes = 0
        self.a_flags = []
        self.b_flags = []
        self.final_flag = ''
        self.dst_host_count = 0
        self.dst_host_srv_count = 0
        self.duration = None
        self.urgents = 0


    def setABytes(self, bytes):
        self.a_bytes += bytes

    def setBBytes(self, bytes):
        self.b_bytes += bytes

    def setAFlags(self, packet_flags):
        self.a_flags.append(packet_flags)

    def setBFlags(self, packet_flags):
        self.b_flags.append(packet_flags)

    def setFinalFlag(self, flag):
        self.final_flag = flag

    def setDstHostCount(self, counter):
        self.dst_host_count = counter

    def setDstHostSrvCount(self, counter):
        self.dst_host_srv_count = counter

    def setDuration(self, duration):
        self.duration = duration

    def setUrgent(self, urg_flag):
        if urg_flag:
            self.urgents += 1

    def __str__(self):
        return (f'Connection: A host - {self.a_addr}:{self.a_port} with {self.a_bytes} bytes - flags: {self.a_flags},\n'
                            f'B host - {self.b_addr}:{self.b_port} with {self.b_bytes} bytes - flags: {self.b_flags},\n'
                            f'final flag = {self.final_flag}, dst_host_count = {self.dst_host_count}, dst_host_srv_count = {self.dst_host_srv_count}')
     

class Duration:

    def __init__(self, first_packet_ts):
        self.first_packet_ts = first_packet_ts
        self.last_packet_ts = 0.0
        self.duration_ts = 0 # should be integer

    def resetLastTs(self, last_packet_ts):
        self.last_packet_ts = last_packet_ts

    def calcDurationTs(self):
        if (self.last_packet_ts > 0.0):
            self.duration_ts = int(round(self.last_packet_ts - self.first_packet_ts))

    def __str__(self):
        return (f'Duration object: fisrt_ts = {self.first_packet_ts}, last_ts = {self.last_packet_ts}, duration int = {self.duration_ts}')

'''
Helper methods
'''

def get_tcp_connections(pcap):
    tcp_session_keys = set()
    syn_fin_packets = {}
    processedKeys = []
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            key = generate_tcp_connection_key(tcp_response)
            if (key not in syn_fin_packets):
                syn_fin_packets[key] = ts
            tcp_session_keys.add(key)
    with open('syn_fin_packets1.txt', 'w') as f:
        for k, v in syn_fin_packets.items():
            f.write(str(k) + ' >>> '+ str(v) + '\n')
    return syn_fin_packets


def generate_tcp_connection_key(tcp_resp):
    tcp = tcp_resp[0]
    s_ip = tcp_resp[1]
    d_ip = tcp_resp[2]
    s_port = tcp.sport
    d_port = tcp.dport
    key =  s_ip + '_' + str(s_port) + '_' + d_ip + '_' + str(d_port)
    return key


def generate_tcp_connection_obj(tcp_resp):
    tcp = tcp_resp[0]
    s_ip = tcp_resp[1]
    d_ip = tcp_resp[2]
    s_port = tcp.sport
    d_port = tcp.dport
    conn = Connection(a_addr=s_ip, a_port=s_port, b_addr=d_ip, b_port=d_port)
    return conn


def if_key_exists(key):
    if(synFinPackets.get(key) is not None):
        return True
    else:
        return False


def detect_tcp(eth):
    if( len(eth.data) > 0 and (eth.type == dpkt.ethernet.ETH_TYPE_IP) ):
        ip = eth.data
        # print ('s_ip - {}, d_ip - {}'.format(inet_to_str(ip.src), inet_to_str(ip.dst)))
        if( len(ip.data) > 0 and (ip.p == dpkt.ip.IP_PROTO_TCP) ):
            return ip.data, inet_to_str(ip.src), inet_to_str(ip.dst)
    return


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


'''
Methods for calculate specific characteristics of traffic
'''

def get_duration_conn_obj(pcap, print_for_debug = False):
    print('get_duration_conn_obj')
    print(infile.tell())
    
    conn_durations_dict = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            conn = generate_tcp_connection_obj(tcp_response)

            if (conn.key in conn_durations_dict):
                stored_conn = conn_durations_dict[conn.key]
                stored_conn.duration.resetLastTs(ts)
                conn_durations_dict[conn.key] = stored_conn
            elif (conn.reversed_key in conn_durations_dict):
                stored_conn = conn_durations_dict[conn.reversed_key]
                stored_conn.duration.resetLastTs(ts)
                conn_durations_dict[conn.reversed_key] = stored_conn
            else:
                duration = Duration(first_packet_ts=ts)
                conn.setDuration(duration)
                conn_durations_dict[conn.key] = conn
    print("conn_durations_dict size - ", len(conn_durations_dict))
    
    duration_list = []
    for conn in conn_durations_dict.values():
        conn.duration.calcDurationTs()
        duration_list.append(conn.duration.duration_ts)
    if print_for_debug:
        with open('get_duration_conn_obj1.txt',mode='w') as f:
            for key, conn in conn_durations_dict.items():
                f.write(str(key) + ' >>> ' + str(conn.duration) + '\n')
    print("durations_list size - ", len(duration_list))
    return duration_list

def get_protocol(pcap):
    # icmp, tcp, udp
    print('get_protocol')

def get_service(pcap):
    print('get_service')

'''
11 флагов
SF - normal establishment and termination.
REJ - connection attempt rejected
S0 - connection attempt seen, no reply
S1 - connection established, not terminated
S2 - connection established and close attempt by originator seen (but no reply from responder)
S3 - connection established and close attempt by responder seen (but no reply from originator)
RSTO - connection reset by originator
RSTR - connection reset by responder
OTH - no SYN seen, just midstream traffic (partial connection that was not later closed)
RSTOS0 - originator sent SYN followed by RST, we never saw SYN-ACK from responder
SH - originator sent SYN followed by FIN, we never saw SYN-ACK from responder (connection was half open)

Connection establishing (3-way handshake):
client -- server
SYN ->
      <- SYN-ACK
ACK ->

Connection termination (4-way handshake):
client -- server
FIN ->
      <- ACK
      <- FIN
ACK ->
'''
def get_flags(pcap):
    print("get_flags")
    conn_flags_dict = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            conn = generate_tcp_connection_obj(tcp_response)
            tcp = tcp_response[0]
            fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
            syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
            rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
            psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
            ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
            urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
            ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
            cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0

            flags = (
            ( "C" if cwr_flag else "" ) +
            ( "E" if ece_flag else "" ) +
            ( "U" if urg_flag else "" ) +
            ( "A" if ack_flag else "" ) +
            ( "P" if psh_flag else "" ) +
            ( "R" if rst_flag else "" ) +
            ( "S" if syn_flag else "" ) +
            ( "F" if fin_flag else "" ) )

            if (conn.key in conn_flags_dict):
                stored_conn = conn_flags_dict[conn.key]
                stored_conn.setAFlags(flags)
                conn_flags_dict[conn.key] = stored_conn
            elif (conn.reversed_key in conn_flags_dict):
                stored_conn = conn_flags_dict[conn.reversed_key]
                stored_conn.setBFlags(flags)
                conn_flags_dict[conn.reversed_key] = stored_conn
            else:
                conn.setAFlags(flags)
                conn_flags_dict[conn.key] = conn

    print("conn_flags_dict size - ", len(conn_flags_dict))
    # with open('get_flags.txt',mode='w') as f:
    #     for k, v in conn_flags_dict.items():
    #         f.write(str(v) + '\n')
    return analyze_flags(conn_flags_dict)

def analyze_flags(conn_flags_dict):
    conn_final_flags_dict = {} # ToDo remove that dict
    for key, conn in conn_flags_dict.items():
        if all(x in conn.a_flags for x in ['S','A','AF']) and all(x in conn.b_flags for x in ['AS','A','AF']):
            # normal establishment and termination -> all est. flags (SYN, SYN-ACK, ACK) + all term. flags (FIN, FIN-ACK, ACK)
            conn_final_flags_dict[key] = 'SF'            
            conn.setFinalFlag('SF')
        elif (len(conn.a_flags) == 2) and (len(conn.b_flags) == 1) and (conn.a_flags[0] == 'S') and (conn.b_flags[0] == 'AS') and (conn.a_flags[1] == 'R'):
            # connection attempt rejected -> est. flags SYN, SYN-ACK + RST (from client)
            conn_final_flags_dict[key] = 'REJ'
            conn.setFinalFlag('REJ')
        elif ('S' in conn.a_flags) and (len(conn.a_flags) == 1) and ('AS' not in conn.b_flags):
            # connection attempt seen, no reply -> SYN only
            conn_final_flags_dict[key] = 'S0'
            conn.setFinalFlag('S0')
        elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and all(x not in conn.a_flags for x in ['F','AF','R','AR']) and all(x not in conn.b_flags for x in ['F','AF','R','AR']):
            # connection established, not terminated -> all est. flags (SYN, SYN-ACK, ACK) 
            conn_final_flags_dict[key] = 'S1'
            conn.setFinalFlag('S1')
        elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('AF' in conn.a_flags) and ('AF' not in conn.b_flags):
            # connection established and close attempt by originator seen (but no reply from responder) -> all est. flags (SYN, SYN-ACK, ACK) + FIN from originator
            conn_final_flags_dict[key] = 'S2'
            conn.setFinalFlag('S2')
        elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('AF' not in conn.a_flags) and ('AF' in conn.b_flags):
            # connection established and close attempt by responder seen (but no reply from originator) -> all est. flags (SYN, SYN-ACK, ACK) + FIN from responder
            conn_final_flags_dict[key] = 'S3'
            conn.setFinalFlag('S3')
        elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('R' in conn.a_flags) and ('R' not in conn.b_flags):
            # connection reset by originator -> all est. flags (SYN, SYN-ACK, ACK) + RST from originator
            conn_final_flags_dict[key] = 'RSTO' # possibly wrong conditions
            conn.setFinalFlag('RSTO')
        elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('R' not in conn.a_flags) and ('R' in conn.b_flags):
            # connection reset by responder -> all est. flags (SYN, SYN-ACK, ACK) + RST from responder
            conn_final_flags_dict[key] = 'RSTR' # possibly wrong conditions
            conn.setFinalFlag('RSTR')
        elif all(x not in conn.a_flags for x in ['S','AF']) and all(x not in conn.b_flags for x in ['AS','AF']):
            # no SYN seen, just midstream traffic (partial connection that was not later closed) -> no est. related flags + no term. related flags
            conn_final_flags_dict[key] = 'OTH'
            conn.setFinalFlag('OTH')
        elif all(x in conn.a_flags for x in ['S','R']) and (len(conn.a_flags) == 2) and ('AS' not in conn.b_flags):
            # originator sent SYN followed by RST, we never saw SYN-ACK from responder -> est. flag SYN + RST (from client)
            conn_final_flags_dict[key] = 'RSTOS0'
            conn.setFinalFlag('RSTOS0')
        elif all(x in conn.a_flags for x in ['S','AF']) and ('AS' not in conn.b_flags):
            # originator sent SYN followed by FIN, we never saw SYN-ACK from responder (connection was half open) -> est. flag SYN + FIN (from client)
            conn_final_flags_dict[key] = 'SH'
            conn.setFinalFlag('SH')
        else:
            conn_final_flags_dict[key] = 'without flag'
            conn.setFinalFlag('without flag')

    # print("conn_final_flags_dict size - ", len(conn_final_flags_dict))
    # with open('analyze_flags1.txt',mode='w') as f:
    #     for k, v in conn_final_flags_dict.items():
    #         f.write(str(k) + ' >>> ' + str(v) + '\n')

    # with open('analyze_flags2.txt',mode='w') as f:
    #     for k, v in conn_flags_dict.items():
    #         f.write(str(v) + '\n')

    return conn_flags_dict


def get_urgents_conn_object(pcap, print_for_debug = False):
    print('get_urgents_conn_object')
    if infile.tell() > 100: # if pcap Reader was already called in previous method we need to reset file cursor and call Reader again  
        infile.seek(0)
        pcap = dpkt.pcap.Reader(infile)
    conn_urgents_dict = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            conn = generate_tcp_connection_obj(tcp_response)
            tcp = tcp_response[0]
            urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
            if (conn.key in conn_urgents_dict):
                stored_conn = conn_urgents_dict[conn.key]
                stored_conn.setUrgent(urg_flag)
                conn_urgents_dict[conn.key] = stored_conn
            elif (conn.reversed_key in conn_urgents_dict):
                stored_conn = conn_urgents_dict[conn.reversed_key]
                stored_conn.setUrgent(urg_flag)
                conn_urgents_dict[conn.reversed_key] = stored_conn
            else:
                conn.setUrgent(urg_flag)
                conn_urgents_dict[conn.key] = conn
    print("conn_urgents_dict size - ", len(conn_urgents_dict))
    if print_for_debug:
        with open('get_urgents.txt',mode='w') as f:
            for k, v in conn_urgents_dict.items():
                f.write(str(v) + '\n')
    urgents_list = [conn.urgents for conn in conn_urgents_dict.values()]
    print("urgents_list size - ", len(urgents_list))
    return urgents_list

def insert_or_update_dict(conn_dict, key, val, increment = False, list_val = False):
    if key not in conn_dict.keys():
        conn_dict[key] = [val]
    else:
        fetched_val = conn_dict[key]
        if type(fetched_val) == list and not increment:
            fetched_val.append(val)
        elif type(fetched_val) == int and val > 0 and increment:
            fetched_val += 1    
        conn_dict[key] = fetched_val



'''
Потенциальная проблема - в некоторых соединения порт А - 443, а порт Б - 5знач порт, например
62.76.174.7:443 with 27620 bytes, B host - 62.76.169.30:37202 with 198 bytes
Тогда как в Wireshark это соединение задано наоборот (443 - во всех случаях это порт Б).
При этом такое же поведение в get_src_bytes1
В остальном разбиение соединения на потоки А->Б (src->dst) и Б->А (dst->src) корректно.
'''
def get_src_dst_bytes(pcap, print_for_debug = False):
    print('get_src_dst_bytes')
    if infile.tell() > 100: # if pcap Reader was already called in previous method we need to reset file cursor and call Reader again  
        infile.seek(0)
        pcap = dpkt.pcap.Reader(infile)
    conn_bytes_dict = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            conn = generate_tcp_connection_obj(tcp_response)
            if (conn.key in conn_bytes_dict):
                stored_conn = conn_bytes_dict[conn.key]
                stored_conn.setABytes(len(buf))
                conn_bytes_dict[conn.key] = stored_conn
            elif (conn.reversed_key in conn_bytes_dict):
                stored_conn = conn_bytes_dict[conn.reversed_key]
                stored_conn.setBBytes(len(buf))
                conn_bytes_dict[conn.reversed_key] = stored_conn
            else:
                conn.setABytes(len(buf))
                conn_bytes_dict[conn.key] = conn

    print('conn_bytes_dict size - ', len(conn_bytes_dict))
    if print_for_debug:
        with open('get_src_bytes2.txt',mode='w') as f:
            for k, v in conn_bytes_dict.items():
                f.write(str(k) + '>>>' + str(v) + '\n')

    src_bytes_list = []
    dst_bytes_list = []
    for conn in conn_bytes_dict.values():
        src_bytes_list.append(conn.a_bytes)
        dst_bytes_list.append(conn.b_bytes)
    return src_bytes_list, dst_bytes_list

# deprecated
def get_dst_host_count(pcap):
    print('get_dst_host_count')
    conn_dict = {}
    dst_host_count_dict = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            conn = generate_tcp_connection_obj(tcp_response)
            if (conn.key not in conn_dict) and (conn.reversed_key not in conn_dict):
                conn_dict[conn.key] = conn
                if (conn.b_addr not in dst_host_count_dict):
                    dst_host_count_dict[conn.b_addr] = 1
                else: 
                    count = dst_host_count_dict[conn.b_addr]
                    count += 1
                    dst_host_count_dict[conn.b_addr] = count

    # need to define the way how to store that char - inside connection obj or smth else

    # for key, conn in conn_dict.items():
    #     for dst_host, count in dst_host_count_dict.items():
    #         if (conn.b_addr == dst_host):

    # print('conn_dict size - ', len(conn_dict))
    # with open('get_dst_host_count.txt',mode='w') as f:
    #     for k, v in conn_dict.items():
    #         f.write(str(k) + '>>>' + str(v) + '\n')
    print('dst_host_count_dict size - ', len(dst_host_count_dict)) 
    with open('dst_host_count_dict.txt',mode='w') as f:
        for k, v in dst_host_count_dict.items():
            f.write(str(k) + '>>>' + str(v) + '\n')

'''
Refactored logic
Reducing execution time

'''
######################################################## 

def get_dst_host_count_v2(conn_dict, print_for_debug = False):
    dst_host_count_dict = {}
    dst_host_srv_count_dict = {}
    for key, conn in conn_dict.items():
        if (conn.b_addr not in dst_host_count_dict):
            dst_host_count_dict[conn.b_addr] = 1
        else:
            count = dst_host_count_dict[conn.b_addr]
            count += 1          
            dst_host_count_dict[conn.b_addr] = count

        if (conn.b_port not in dst_host_srv_count_dict):
            dst_host_srv_count_dict[conn.b_port] = 1
        else:
            count = dst_host_srv_count_dict[conn.b_port]
            count += 1          
            dst_host_srv_count_dict[conn.b_port] = count
    # how to implement without doulble loop?
    for key, conn in conn_dict.items():
        if (conn.b_addr in dst_host_count_dict):
            conn.setDstHostCount(dst_host_count_dict[conn.b_addr])
        if (conn.b_port in dst_host_srv_count_dict):
            conn.setDstHostSrvCount(dst_host_srv_count_dict[conn.b_port])

    print('dst_host_count_dict size - ', len(dst_host_count_dict))
    print('dst_host_srv_count_dict size - ', len(dst_host_srv_count_dict))
    if print_for_debug:
        with open('dst_host_srv_count_dict.txt',mode='w') as f:
            for k, v in dst_host_srv_count_dict.items():
                f.write(str(k) + '_' + str(v) + '\n')
        with open('dst_host_count_dict_v2.txt',mode='w') as f:
            for k, v in conn_dict.items():
                f.write(str(v) + '\n')
    return conn_dict

def get_count_srv_count(conn_dict, print_for_debug = False):
    print("get_count_srv_count")
    for key, conn in conn_dict.items():
        dest_ip = conn.b_addr
        # проверяем по объекту duration внутри conn 
        # для текущ соединения берем 


# put here dst host srv serror rerror rate
def get_dst_host_serror_rerror_rate(conn_dict, print_for_debug = False):
    print('get_dst_host_serror_rerror_rate')
    # get all connections with same Dst Host Count, get num of connections with flags s0-s3 among them, calc % of all number of connections in that group
    # new dict with : dst_host_ip - num_of_s0_s3_conn - all_num_of_conn_with_that_ip
    # iterate over conn_dict and fill that dict  
    dst_host_error_rate_dict = {}  # key - conn b_addr with postfix 'S' or 'REJ', val - list of [num_of_s0_s3_conn,dst_host_count]
    for key, conn in conn_dict.items():
        if (conn.final_flag == 'S0') or (conn.final_flag == 'S1') or (conn.final_flag == 'S2') or (conn.final_flag == 'S3'):
            dst_host_key = conn.b_addr + '_' + 'S'
            dst_host_srv_key = str(conn.b_port) + '_' + 'S'
            if (dst_host_key not in dst_host_error_rate_dict):
                dst_host_error_rate_dict[dst_host_key] = [1,conn.dst_host_count]
            else:
                count = dst_host_error_rate_dict[dst_host_key][0]
                count += 1
                dst_host_error_rate_dict[dst_host_key][0] = count

            if (dst_host_srv_key not in dst_host_error_rate_dict):
                dst_host_error_rate_dict[dst_host_srv_key] = [1,conn.dst_host_srv_count]
            else:
                count = dst_host_error_rate_dict[dst_host_srv_key][0]
                count += 1
                dst_host_error_rate_dict[dst_host_srv_key][0] = count
        elif (conn.final_flag == 'REJ'):
            dst_host_key = conn.b_addr + '_' + 'REJ'
            dst_host_srv_key = str(conn.b_port) + '_' + 'REJ'
            if (dst_host_key not in dst_host_error_rate_dict):
                dst_host_error_rate_dict[dst_host_key] = [1,conn.dst_host_count]
            else:
                count = dst_host_error_rate_dict[dst_host_key][0]
                count += 1
                dst_host_error_rate_dict[dst_host_key][0] = count

            if (dst_host_srv_key not in dst_host_error_rate_dict):
                dst_host_error_rate_dict[dst_host_srv_key] = [1,conn.dst_host_srv_count]
            else:
                count = dst_host_error_rate_dict[dst_host_srv_key][0]
                count += 1
                dst_host_error_rate_dict[dst_host_srv_key][0] = count

    dst_host_serror_rate_list = []
    dst_host_rerror_rate_list = []
    dst_host_srv_serror_rate_list = []
    dst_host_srv_rerror_rate_list = []

    for key, conn in conn_dict.items():
        if (conn.final_flag == 'S0') or (conn.final_flag == 'S1') or (conn.final_flag == 'S2') or (conn.final_flag == 'S3'):
            dst_host_key = conn.b_addr + '_' + 'S'
            dst_host_srv_key = str(conn.b_port) + '_' + 'S'

            flagged_serror_conn_count = dst_host_error_rate_dict[dst_host_key][0]
            dst_host_count = dst_host_error_rate_dict[dst_host_key][1]
            serror_rate = round((flagged_serror_conn_count / dst_host_count), 2)

            flagged_srv_serror_conn_count = dst_host_error_rate_dict[dst_host_srv_key][0]
            dst_host_srv_count = dst_host_error_rate_dict[dst_host_srv_key][1]
            srv_serror_rate = round((flagged_srv_serror_conn_count / dst_host_srv_count), 2)           

            dst_host_serror_rate_list.append(serror_rate)
            dst_host_srv_serror_rate_list.append(srv_serror_rate)
        else:
            dst_host_serror_rate_list.append(0)
            dst_host_srv_serror_rate_list.append(0)

        if (conn.final_flag == 'REJ'):
            dst_host_key = conn.b_addr + '_' + 'REJ'
            dst_host_srv_key = str(conn.b_port) + '_' + 'REJ'

            flagged_rerror_conn_count = dst_host_error_rate_dict[dst_host_key][0]
            dst_host_count = dst_host_error_rate_dict[dst_host_key][1]
            rerror_rate = round((flagged_rerror_conn_count / dst_host_count), 2)

            flagged_srv_rerror_conn_count = dst_host_error_rate_dict[dst_host_srv_key][0]
            dst_host_srv_count = dst_host_error_rate_dict[dst_host_srv_key][1]
            srv_rerror_rate = round((flagged_srv_rerror_conn_count / dst_host_srv_count), 2)    

            dst_host_rerror_rate_list.append(rerror_rate)
            dst_host_srv_rerror_rate_list.append(srv_rerror_rate)
        else:
            dst_host_rerror_rate_list.append(0)
            dst_host_srv_rerror_rate_list.append(0)
    
    print('dst_host_error_rate_dict size - ', len(dst_host_error_rate_dict))    

    print(f'dst_host_serror_rate_list size - {len(dst_host_serror_rate_list)},\n'
          f'dst_host_rerror_rate_list size - {len(dst_host_rerror_rate_list)},\n'
          f'dst_host_srv_serror_rate_list size - {len(dst_host_srv_serror_rate_list)},\n'
          f'dst_host_srv_rerror_rate_list size - {len(dst_host_srv_rerror_rate_list)}')
    if print_for_debug:
        with open('dst_host_error_rate_dict.txt',mode='w') as f:
            for k, v in dst_host_error_rate_dict.items():
                f.write(str(k) + '_' + str(v) + '\n')
    return dst_host_serror_rate_list, dst_host_rerror_rate_list, dst_host_srv_serror_rate_list, dst_host_srv_rerror_rate_list


def get_duration_for_conn(ts, conn, conn_durations_dict):
    if (conn.key in conn_durations_dict):
        stored_conn = conn_durations_dict[conn.key]
        stored_conn.duration.resetLastTs(ts)
        conn_durations_dict[conn.key] = stored_conn
    elif (conn.reversed_key in conn_durations_dict):
        stored_conn = conn_durations_dict[conn.reversed_key]
        stored_conn.duration.resetLastTs(ts)
        conn_durations_dict[conn.reversed_key] = stored_conn
    else:
        duration = Duration(first_packet_ts=ts)
        conn.setDuration(duration)
        conn_durations_dict[conn.key] = conn

def get_urgents_for_conn(tcp_response, conn, conn_urgents_dict):
    tcp = tcp_response[0]
    urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
    if (conn.key in conn_urgents_dict):
        stored_conn = conn_urgents_dict[conn.key]
        stored_conn.setUrgent(urg_flag)
        conn_urgents_dict[conn.key] = stored_conn
    elif (conn.reversed_key in conn_urgents_dict):
        stored_conn = conn_urgents_dict[conn.reversed_key]
        stored_conn.setUrgent(urg_flag)
        conn_urgents_dict[conn.reversed_key] = stored_conn
    else:
        conn.setUrgent(urg_flag)
        conn_urgents_dict[conn.key] = conn

def get_flags_for_conn(tcp_response, conn, conn_flags_dict):
    tcp = tcp_response[0]
    fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
    syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
    rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
    psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
    ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
    urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
    ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
    cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0

    flags = (
    ( "C" if cwr_flag else "" ) +
    ( "E" if ece_flag else "" ) +
    ( "U" if urg_flag else "" ) +
    ( "A" if ack_flag else "" ) +
    ( "P" if psh_flag else "" ) +
    ( "R" if rst_flag else "" ) +
    ( "S" if syn_flag else "" ) +
    ( "F" if fin_flag else "" ) )

    if (conn.key in conn_flags_dict):
        stored_conn = conn_flags_dict[conn.key]
        stored_conn.setAFlags(flags)
        conn_flags_dict[conn.key] = stored_conn
    elif (conn.reversed_key in conn_flags_dict):
        stored_conn = conn_flags_dict[conn.reversed_key]
        stored_conn.setBFlags(flags)
        conn_flags_dict[conn.reversed_key] = stored_conn
    else:
        conn.setAFlags(flags)
        conn_flags_dict[conn.key] = conn

def analyze_flags_for_conn(conn):
    if all(x in conn.a_flags for x in ['S','A','AF']) and all(x in conn.b_flags for x in ['AS','A','AF']):
        # normal establishment and termination -> all est. flags (SYN, SYN-ACK, ACK) + all term. flags (FIN, FIN-ACK, ACK)           
        conn.setFinalFlag('SF')
    elif (len(conn.a_flags) == 2) and (len(conn.b_flags) == 1) and (conn.a_flags[0] == 'S') and (conn.b_flags[0] == 'AS') and (conn.a_flags[1] == 'R'):
        # connection attempt rejected -> est. flags SYN, SYN-ACK + RST (from client)
        conn.setFinalFlag('REJ')
    elif ('S' in conn.a_flags) and (len(conn.a_flags) == 1) and ('AS' not in conn.b_flags):
        # connection attempt seen, no reply -> SYN only
        conn.setFinalFlag('S0')
    elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and all(x not in conn.a_flags for x in ['F','AF','R','AR']) and all(x not in conn.b_flags for x in ['F','AF','R','AR']):
        # connection established, not terminated -> all est. flags (SYN, SYN-ACK, ACK) 
        conn.setFinalFlag('S1')
    elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('AF' in conn.a_flags) and ('AF' not in conn.b_flags):
        # connection established and close attempt by originator seen (but no reply from responder) -> all est. flags (SYN, SYN-ACK, ACK) + FIN from originator
        conn.setFinalFlag('S2')
    elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('AF' not in conn.a_flags) and ('AF' in conn.b_flags):
        # connection established and close attempt by responder seen (but no reply from originator) -> all est. flags (SYN, SYN-ACK, ACK) + FIN from responder
        conn.setFinalFlag('S3')
    elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('R' in conn.a_flags) and ('R' not in conn.b_flags):
        # connection reset by originator -> all est. flags (SYN, SYN-ACK, ACK) + RST from originator
        conn.setFinalFlag('RSTO')
    elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('R' not in conn.a_flags) and ('R' in conn.b_flags):
        # connection reset by responder -> all est. flags (SYN, SYN-ACK, ACK) + RST from responder
        conn.setFinalFlag('RSTR')
    elif all(x not in conn.a_flags for x in ['S','AF']) and all(x not in conn.b_flags for x in ['AS','AF']):
        # no SYN seen, just midstream traffic (partial connection that was not later closed) -> no est. related flags + no term. related flags
        conn.setFinalFlag('OTH')
    elif all(x in conn.a_flags for x in ['S','R']) and (len(conn.a_flags) == 2) and ('AS' not in conn.b_flags):
        # originator sent SYN followed by RST, we never saw SYN-ACK from responder -> est. flag SYN + RST (from client)
        conn.setFinalFlag('RSTOS0')
    elif all(x in conn.a_flags for x in ['S','AF']) and ('AS' not in conn.b_flags):
        # originator sent SYN followed by FIN, we never saw SYN-ACK from responder (connection was half open) -> est. flag SYN + FIN (from client)
        conn.setFinalFlag('SH')
    else:
        conn.setFinalFlag('without flag')

# returns numeric representation of flag
# order based on https://github.com/jmnwong/NSL-KDD-Dataset/blob/master/KDDTest%2B.arff
def get_int_flag(str_flag):
    map_str_to_int_flag_dict = {'OTH':1,'REJ':2,'RSTO':3,'RSTOS0':4,'RSTR':5,'S0':6,'S1':7,'S2':8,'S3':9,'SF':10,'SH':11,'without flag':12}
    return map_str_to_int_flag_dict[str_flag]

def get_src_dst_bytes_for_conn(buf, conn, conn_bytes_dict):
    if (conn.key in conn_bytes_dict):
        stored_conn = conn_bytes_dict[conn.key]
        stored_conn.setABytes(len(buf))
        conn_bytes_dict[conn.key] = stored_conn
    elif (conn.reversed_key in conn_bytes_dict):
        stored_conn = conn_bytes_dict[conn.reversed_key]
        stored_conn.setBBytes(len(buf))
        conn_bytes_dict[conn.reversed_key] = stored_conn
    else:
        conn.setABytes(len(buf))
        conn_bytes_dict[conn.key] = conn

def identify_connections(pcap, attack_label, print_for_debug = False):
    print('identify_connections')
    conn_dict = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            conn = generate_tcp_connection_obj(tcp_response)

            get_duration_for_conn(ts, conn, conn_dict)
            get_urgents_for_conn(tcp_response, conn, conn_dict)
            get_flags_for_conn(tcp_response, conn, conn_dict)
            get_src_dst_bytes_for_conn(buf, conn, conn_dict)

    print("conn_dict size - ", len(conn_dict))
    
    # looks ugly, refactor - possible move it in for loop above
    conn_dict = get_dst_host_count_v2(conn_dict)

    keys_list = [] # for debug purpose
    duration_list = []
    flags_list = []
    src_bytes_list = []
    dst_bytes_list = []
    urgents_list = []
    dst_host_count_list = []
    dst_host_srv_count_list = []
    for key, conn in conn_dict.items():
        # filling list with connections keys for debug purpose
        keys_list.append(key)
        # calc and set duration
        conn.duration.calcDurationTs()
        duration_list.append(conn.duration.duration_ts)
        # calc and set flag
        analyze_flags_for_conn(conn)
        flags_list.append(get_int_flag(conn.final_flag))
        # set src-dst bytes
        src_bytes_list.append(conn.a_bytes)          
        dst_bytes_list.append(conn.b_bytes)
        # set urgents
        urgents_list.append(conn.urgents)
        # set dst host count
        dst_host_count_list.append(conn.dst_host_count)
        # set dst host srv count 
        dst_host_srv_count_list.append(conn.dst_host_srv_count)

    # secondary characteristics (dependent)
    dst_host_serror_rate_list, dst_host_rerror_rate_list, dst_host_srv_serror_rate_list, dst_host_srv_rerror_rate_list = get_dst_host_serror_rerror_rate(conn_dict, True)

    if print_for_debug:
        with open('identify_connections_dict.txt',mode='w') as f:
            for k, v in conn_dict.items():
                f.write(str(k) + '_' + str(v) + '\n')

    print(f'duration_list size - {len(duration_list)}')
    print(f'flags_list size - {len(flags_list)}')
    print(f'src_bytes_list size - {len(src_bytes_list)}')
    print(f'dst_bytes_list size - {len(dst_bytes_list)}')
    print(f'dst_host_count_list size - {len(dst_host_count_list)}')

    # urgents_list = [conn.urgents for conn in conn_dict.values()]
    # print(f'urgents_list size - {len(urgents_list)}, type - {type(urgents_list)}')

    if attack_label:
        # Setting attack label. Needed for further processing by neural network.
        if (attack_label == '0') or (attack_label == 'False'):
            attack_labels_list = [0] * len(conn_dict)
        elif (attack_label == '1') or (attack_label == 'True'):
            attack_labels_list = [1] * len(conn_dict)
        return zip(duration_list, src_bytes_list, dst_bytes_list, urgents_list, dst_host_count_list, dst_host_srv_count_list, 
               dst_host_serror_rate_list, dst_host_srv_serror_rate_list, dst_host_rerror_rate_list, 
               dst_host_srv_rerror_rate_list, flags_list, attack_labels_list)        

    return zip(duration_list, src_bytes_list, dst_bytes_list, urgents_list, dst_host_count_list, dst_host_srv_count_list, 
               dst_host_serror_rate_list, dst_host_srv_serror_rate_list, dst_host_rerror_rate_list, 
               dst_host_srv_rerror_rate_list, flags_list)

def generate_final_csv(rows, fileName):
    print('generate_final_csv')
    # print(Lists)
    # rows = zip(*Lists)
    with open(fileName + '_chars.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        for row in rows:
            writer.writerow(row)

def get_file_name_from_path(filePath):
    fileNameBase = os.path.basename(filePath)
    fileName = os.path.splitext(fileNameBase)[0] # to fetch name without extension
    print(f"fileName - {fileName}")
    return fileName

def main(argv):
    print("argv - ", argv)
    opts, args = getopt.getopt(argv, "hf:a:", ["help", "filePath=", "attack="])
    attackLabel = ""
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("Usage: python [script_name] -f [file path] -a [set attack label]\n"
                  "-f, --filePath     full path to pcap file which need to be processsed. If -f not set, \n" 
                  "                   then using global var globalFilePath. \n"
                  "-a, --attackLabel  setting attack label. Possible values: 0 (False) - normal traffic, \n"
                  "                   1 (True) - attack traffic")
            sys.exit()
        elif opt in ("-f", "--filePath"):
            filePath = arg
            infile = open(filePath, 'rb')
            fileName = get_file_name_from_path(filePath)
        elif opt in ("-a", "--attackLabel"):
            attackLabel = arg
            print(f"attackLabel - {attackLabel}, type - {type(attackLabel)}")
            if attackLabel not in ("0", "1", "True", "False"):
                print("Unrecognized attack label")
                attackLabel = ""

    
    if not argv:
        print("No args were transmited, using globalFilePath")
        infile = open(globalFilePath, 'rb')
        fileName = get_file_name_from_path(globalFilePath)

    pcap = dpkt.pcap.Reader(infile)
    # duration_list = get_duration(pcap, True)
    # duration_list = get_duration_conn_obj(pcap, True)
    # urgents_list = get_urgents(pcap)
    # urgents_list = get_urgents_conn_object(pcap, True)
    # src_bytes_list, dst_bytes_list = get_src_dst_bytes(pcap)

    # conn_dict = get_flags(pcap)
    # conn_dict1 = get_dst_host_count_v2(conn_dict)
    # get_dst_host_serror_rate(conn_dict1)
    
    # generate_final_csv(duration_list, urgents_list, src_bytes_list, dst_bytes_list)
    
    # list1, list2, list3 = identify_connections(pcap)
    # generate_final_csv(list1, list2, list3) 

    generate_final_csv(identify_connections(pcap, attackLabel, True), fileName)
 
if __name__ == '__main__':
    main(sys.argv[1:])
