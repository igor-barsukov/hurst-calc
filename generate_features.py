import dpkt
import socket

# infile = open('D:/Aspirantura/traffic/moodle_2020/testfile.2020-06-07.%H.%M.%S.pcap', 'rb')
infile = open('C:\\Users\\igba0714\\Documents\\Studying\\Postgrade\\moodle_2020\\testfile.2020-06-07.%H.%M.%S.pcap', 'rb')

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

# def get_flags_for_connection(tcp_resp):
#     conn_key = generate_tcp_connection_key(tcp_resp)

# obsolete
def get_duration1(pcap):
    # идея - не проверять флаги, а просто сканировать для каждого соединения, находить 1й и последний и по разнице ts выводить duration
    print('get_duration')
    syn_fin_packets = get_tcp_connections(pcap)
    print('syn_fin_packets size - ', len(syn_fin_packets))

    infile.seek(0)  # to reset cursor and read file again
    pcap = dpkt.pcap.Reader(infile)
    syn_fin_packets_2 = {}
    for ts, buf in pcap:
        # print('here1 - ', len(buf))
        eth = dpkt.ethernet.Ethernet(buf)
        tcp_response = detect_tcp(eth)
        if(tcp_response is not None):
            tcp = tcp_response[0]
            s_ip = tcp_response[1]
            d_ip = tcp_response[2]
            s_port = tcp.sport
            d_port = tcp.dport
            scanned_key =  s_ip + '_' + d_ip + '_' + str(s_port) + '_' + str(d_port)
            # print('scanned_key - ', scanned_key)
            for key, val in syn_fin_packets.items():
                last_ts_val = 0.0
                if (scanned_key == key):
                    # print('matched key  - ', key)
                    last_ts_val = ts
            print('here')
            dur = last_ts_val - val
            syn_fin_packets_2[key] = dur

    # for key, val in syn_fin_packets.items():
    #     last_ts_val = 0.0
    #     # print('key        - ', key)
    #     # f.write('key        - ' + key + '\n')
    #     # print('pcap type - ', type(pcap))
    #     infile = open('D:/Aspirantura/traffic/moodle_2020/testfile.2020-06-07.%H.%M.%S.pcap', 'rb')
    #     pcap1 = dpkt.pcap.Reader(infile)
    #     for ts, buf in pcap1:
    #         # print('here')
    #         # f.write('here' + '\n')
    #         eth = dpkt.ethernet.Ethernet(buf)
    #         tcp_response = detect_tcp(eth)
    #         if(tcp_response is not None):
    #             tcp = tcp_response[0]
    #             s_ip = tcp_response[1]
    #             d_ip = tcp_response[2]
    #             s_port = tcp.sport
    #             d_port = tcp.dport
    #             scanned_key =  s_ip + '_' + d_ip + '_' + str(s_port) + '_' + str(d_port)
    #             # print('matched key - ', scanned_key)
    #             # f.write('scanned_key  -' + scanned_key + '\n')
    #             if (scanned_key == key):
    #                 # f.write('matched key  -' + scanned_key + '\n')
    #                 last_ts_val = ts
    #     dur = last_ts_val - val
    #     syn_fin_packets[key] = dur
    with open('syn_fin_packets3.txt', 'w') as f:
        for k, v in syn_fin_packets_2.items():
            f.write(str(k) + ' >>> '+ str(v) + '\n')

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
            conn_durations_new_dict[k] = v[1] - v[0]
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

def get_flag(pcap):
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
    print('get_flag')
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
            ( "C" if cwr_flag else " " ) +
            ( "E" if ece_flag else " " ) +
            ( "U" if urg_flag else " " ) +
            ( "A" if ack_flag else " " ) +
            ( "P" if psh_flag else " " ) +
            ( "R" if rst_flag else " " ) +
            ( "S" if syn_flag else " " ) +
            ( "F" if fin_flag else " " ) )

            insert_or_update_dict(conn_flags_dict, key, flags + " " + str(ts), list_val = True)

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
            elif rst_flag and not rst_flag:
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
            f.write(str(k) + ' >>> ' + str(v) + '\n')


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

# сейчас считывает полное число байт в обе стороны, совпадает с полем Bytes в шарке
# как определить кол-во байт в разные стороны? по флагам?
# syn(1),ack(0) - от клиента, syn(1),ack(1) - от сервера, syn(0),ack(1) - от клиента
# ("All packets after the initial SYN packet sent by the client should have ACK flag set.")
def get_src_bytes(pcap):
    print('get_src_bytes')
    syn_fin_packets = get_tcp_connections(pcap)
    conn_bytes_dict = {}
    print('syn_fin_packets size - ', len(syn_fin_packets))
    for key in syn_fin_packets.keys():
        infile.seek(0)  # to reset cursor and read file again
        pcap = dpkt.pcap.Reader(infile)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            tcp_response = detect_tcp(eth)
            if(tcp_response is not None):
                scanned_key = generate_tcp_connection_key(tcp_response)
                if (scanned_key == key):
                    if (key not in conn_bytes_dict):
                        conn_bytes_dict[scanned_key] = len(buf)
                    else:
                        bytes_count = conn_bytes_dict[scanned_key]
                        bytes_count = bytes_count + len(buf)
                        conn_bytes_dict[scanned_key] = bytes_count
    print('conn_bytes_dict size - ', len(conn_bytes_dict))
    # with open('get_src_bytes.txt',mode='w') as f:
    #     for k, v in conn_bytes_dict.items():
    #         f.write(str(k) + ' >>> ' + str(v) + '\n')

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

def get_dst_bytes(pcap):
    print('get_dst_bytes')

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

def main():
    pcap = dpkt.pcap.Reader(infile)
    # get_duration1(pcap)
    # get_src_bytes1(pcap)
    # get_duration2(pcap)
    # get_flag(pcap)
    get_urgents(pcap)

if __name__ == '__main__':
    main()
