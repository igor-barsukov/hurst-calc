import dpkt
import socket

# infile = open('D:/Aspirantura/traffic/moodle_2020/testfile.2020-06-07.%H.%M.%S.pcap', 'rb')
infile = open('C:\\Users\\igba0714\\Documents\\Studying\\Postgrade\\moodle_2020\\2020-11-16-22-11.pcap\\testfile.2020-11-16.%H.%M.%S.pcap', 'rb')

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


    def setABytes(self, bytes):
        self.a_bytes += bytes

    def setBBytes(self, bytes):
        self.b_bytes += bytes

    def setAFlags(self, packet_flags):
        self.a_flags.append(packet_flags)

    def setBFlags(self, packet_flags):
        self.b_flags.append(packet_flags)

    def __str__(self):
        return (f'Connection: A host - {self.a_addr}:{self.a_port} with {self.a_bytes} bytes - flags: {self.a_flags},\n'
                            f'B host - {self.b_addr}:{self.b_port} with {self.b_bytes} bytes - flags: {self.b_flags}')
     

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
    key =  s_ip + '_' + d_ip + '_' + str(s_port) + '_' + str(d_port)
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

# obsolete
def get_duration(pcap):
    print('get_duration')
    tcp_session_keys = set()
    syn_fin_packets = {}
    processedKeys = []
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            tcp = tcp_response[0]
            s_ip = tcp_response[1]
            d_ip = tcp_response[2]
            s_port = tcp.sport
            d_port = tcp.dport
            key =  s_ip + '_' + d_ip + '_' + str(s_port) + '_' + str(d_port)
            tcp_session_keys.add(key)
            if( (tcp.flags & dpkt.tcp.TH_SYN) != 0 and ( tcp.flags & dpkt.tcp.TH_ACK ) == 0 and (key not in syn_fin_packets)):
                syn_fin_packets[key] = ts
            elif( (tcp.flags & dpkt.tcp.TH_FIN) != 0 and (key not in processedKeys) ):
                if( key in syn_fin_packets ):
                    timeInterval = ts - syn_fin_packets.get(key)
                    syn_fin_packets[key] = timeInterval
                    processedKeys.append(key)
            # идея - не проверять флаги, а просто сканировать для каждого соединения, находить 1й и последний и по разнице ts выводить duration
    print('sess num:', len(tcp_session_keys))
    print('processedKeys num:', len(processedKeys))
    # with open('tcp_session_keys.txt', 'w') as f:
    #     for item in tcp_session_keys:
    #         f.write("%s\n" % item)
    # with open('syn_fin_packets.txt', 'w') as f:
    #     for k, v in syn_fin_packets.items():
    #         f.write(str(k) + ' >>> '+ str(v) + '\n\n')


def get_duration2(pcap):
    print('get_duration2')
    conn_durations_dict = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            key = generate_tcp_connection_key(tcp_response)
            if(key not in conn_durations_dict):
                conn_durations_dict[key] = [ts] # set ts of first packet of this connection at 1st position of list
            elif(conn_durations_dict[key] is not None and len(conn_durations_dict[key]) == 1):
                # set ts of second packet of this connection at 2nd position of list
                ts_list = conn_durations_dict[key]
                ts_list.append(ts)
                conn_durations_dict[key] = ts_list
            elif(conn_durations_dict[key] is not None and len(conn_durations_dict[key]) == 2):
                conn_durations_dict[key][1] = ts # reset ts of each next packet of this connection on 2nd position of list
    print("conn_durations_dict size - ", len(conn_durations_dict))
    with open('get_duration2_temp.txt',mode='w') as f:
        for k, v in conn_durations_dict.items():
            f.write(str(k) + ' >>> ' + str(v) + '\n')
    conn_durations_new_dict = {}
    for k, v in conn_durations_dict.items():
        if(len(v) > 1):
            conn_durations_new_dict[k] = v[1] - v[0] # calculate duration as difference between last and 1st packet
        else:
            conn_durations_new_dict[k] = 0.0  # in case if only one packet for connection is present
    print("conn_durations_new_dict size - ", len(conn_durations_new_dict))
    with open('get_duration2.txt',mode='w') as f:
        for k, v in conn_durations_new_dict.items():
            f.write(str(k) + ' >>> ' + str(v) + '\n')

def get_protocol(pcap):
    # icmp, tcp, udp
    print('get_protocol')

def get_service(pcap):
    print('get_service')

def get_flags(pcap):
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
    print('get_flags')
    conn_flags_dict = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            key = generate_tcp_connection_key(tcp_response)
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

            insert_or_update_dict(conn_flags_dict, key, flags, list_val = True)

            if syn_flag and not ack_flag:
                # connection establishing 1 - client send SYN to server ->
                # S0 flag?
                pass
            elif syn_flag and ack_flag:
                # connection establishing 2 - server send SYN-ACK to client <-
                # 
                pass
            elif not syn_flag and ack_flag:
                # connection establishing 3 - client send ACK to server ->
                # or it may be connecting terminating phase - either ACK from server to client or final ACK from client to server
                # S1 flag?
                pass
            elif fin_flag:
                # connection terminating - either begining FIN from client to server or FIN from server to client
                # SF flag?
                pass
            elif ack_flag and rst_flag:
                # indicates that port is closed
                pass
            elif rst_flag and not ack_flag:
                # connection refused - server sends RST to client's 1st SYN
                # in other words - receiver sends RST to the sender when a packet is sent to a particular host that was not expecting it.
                # REJ flag?
                pass
            elif urg_flag:
                pass
    print("conn_flags_dict size - ", len(conn_flags_dict))
    with open('get_flags.txt',mode='w') as f:
        for k, v in conn_flags_dict.items():
            f.write(str(k) + ' >>> ' + str(v) + '\n')

def get_flags1(pcap):
    print("get_flags1")
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
    # with open('get_flags1.txt',mode='w') as f:
    #     for k, v in conn_flags_dict.items():
    #         f.write(str(v) + '\n')
    analyze_flags(conn_flags_dict)

def analyze_flags(conn_flags_dict):
    conn_final_flags_dict = {}
    for key, conn in conn_flags_dict.items():
        if all(x in conn.a_flags for x in ['S','A','AF']) and all(x in conn.b_flags for x in ['AS','A','AF']):
            # normal establishment and termination -> all est. flags (SYN, SYN-ACK, ACK) + all term. flags (FIN, FIN-ACK, ACK)
            conn_final_flags_dict[key] = 'SF'
        elif (len(conn.a_flags) == 2) and (len(conn.b_flags) == 1) and (conn.a_flags[0] == 'S') and (conn.b_flags[0] == 'AS') and (conn.a_flags[1] == 'R'):
            # connection attempt rejected -> est. flags SYN, SYN-ACK + RST (from client)
            conn_final_flags_dict[key] = 'REJ'
        elif ('S' in conn.a_flags) and (len(conn.a_flags) == 1) and ('AS' not in conn.b_flags):
            # connection attempt seen, no reply -> SYN only
            conn_final_flags_dict[key] = 'S0'
        elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and all(x not in conn.a_flags for x in ['F','AF','R','AR']) and all(x not in conn.b_flags for x in ['F','AF','R','AR']):
            # connection established, not terminated -> all est. flags (SYN, SYN-ACK, ACK) 
            conn_final_flags_dict[key] = 'S1'
        elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('AF' in conn.a_flags) and ('AF' not in conn.b_flags):
            # connection established and close attempt by originator seen (but no reply from responder) -> all est. flags (SYN, SYN-ACK, ACK) + FIN from originator
            conn_final_flags_dict[key] = 'S2'
        elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('AF' not in conn.a_flags) and ('AF' in conn.b_flags):
            # connection established and close attempt by responder seen (but no reply from originator) -> all est. flags (SYN, SYN-ACK, ACK) + FIN from responder
            conn_final_flags_dict[key] = 'S3'
        elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('R' in conn.a_flags) and ('R' not in conn.b_flags):
            # connection reset by originator -> all est. flags (SYN, SYN-ACK, ACK) + RST from originator
            conn_final_flags_dict[key] = 'RSTO' # possibly wrong conditions
        elif all(x in conn.a_flags for x in ['S','A']) and ('AS' in conn.b_flags) and ('R' not in conn.a_flags) and ('R' in conn.b_flags):
            # connection reset by responder -> all est. flags (SYN, SYN-ACK, ACK) + RST from responder
            conn_final_flags_dict[key] = 'RSTR' # possibly wrong conditions
        elif all(x not in conn.a_flags for x in ['S','AF']) and all(x not in conn.b_flags for x in ['AS','AF']):
            # no SYN seen, just midstream traffic (partial connection that was not later closed) -> no est. related flags + no term. related flags
            conn_final_flags_dict[key] = 'OTH'
        elif all(x in conn.a_flags for x in ['S','R']) and (len(conn.a_flags) == 2) and ('AS' not in conn.b_flags):
            # originator sent SYN followed by RST, we never saw SYN-ACK from responder -> est. flag SYN + RST (from client)
            conn_final_flags_dict[key] = 'RSTOS0'
        elif all(x in conn.a_flags for x in ['S','AF']) and ('AS' not in conn.b_flags):
            # originator sent SYN followed by FIN, we never saw SYN-ACK from responder (connection was half open) -> est. flag SYN + FIN (from client)
            conn_final_flags_dict[key] = 'SH'
        else:
            conn_final_flags_dict[key] = 'without flag'

    print("conn_final_flags_dict size - ", len(conn_final_flags_dict))
    with open('analyze_flags1.txt',mode='w') as f:
        for k, v in conn_final_flags_dict.items():
            f.write(str(k) + ' >>> ' + str(v) + '\n')


def get_urgents(pcap):
    print('get_urgents')
    conn_urgents_dict = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            key = generate_tcp_connection_key(tcp_response)
            tcp = tcp_response[0]
            urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
            if urg_flag:
                insert_or_update_dict(conn_urgents_dict, key, 1, increment = True)
            else:
                insert_or_update_dict(conn_urgents_dict, key, 0, increment = True)
    print("conn_urgents_dict size - ", len(conn_urgents_dict))
    with open('get_urgents.txt',mode='w') as f:
        for k, v in conn_urgents_dict.items():
            f.write(str(v) + '\n')


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


# obsolete (считывает полное число байт в обе стороны, совпадает с полем Bytes в шарке)
def get_src_bytes1(pcap):
    conn_bytes_dict = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            key = generate_tcp_connection_key(tcp_response)
            if (key not in conn_bytes_dict):
                conn_bytes_dict[key] = len(buf)
            else:
                bytes_count = conn_bytes_dict[key]
                bytes_count = bytes_count + len(buf)
                conn_bytes_dict[key] = bytes_count
    print('conn_bytes_dict size - ', len(conn_bytes_dict))
    with open('get_src_bytes1.txt',mode='w') as f:
        for k, v in conn_bytes_dict.items():
            f.write(str(k) + ' >>> ' + str(v) + '\n')


'''
Потенциальная проблема - в некоторых соединения порт А - 443, а порт Б - 5знач порт, например
62.76.174.7:443 with 27620 bytes, B host - 62.76.169.30:37202 with 198 bytes
Тогда как в Wireshark это соединение задано наоборот (443 - во всех случаях это порт Б).
При этом такое же поведение в get_src_bytes1
В остальном разбиение соединения на потоки А->Б (src->dst) и Б->А (dst->src) корректно.
Переименовать этот метод.
'''
def get_src_bytes2(pcap):
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
    with open('get_src_bytes2.txt',mode='w') as f:
        for k, v in conn_bytes_dict.items():
            f.write(str(v) + '\n')


def get_dst_bytes(pcap):
    print('get_dst_bytes')


def main():
    pcap = dpkt.pcap.Reader(infile)
    # get_src_bytes1(pcap)
    # get_duration2(pcap)
    # get_flags(pcap)
    # get_urgents(pcap)
    # get_src_bytes2(pcap)
    get_flags1(pcap)

if __name__ == '__main__':
    main()
