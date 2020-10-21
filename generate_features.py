import dpkt
import socket

# infile = open('D:/Aspirantura/traffic/moodle_2020/testfile.2020-06-06.%H.%M.%S.pcap', 'rb')
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
    print('get_flag')

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
    get_duration2(pcap)

if __name__ == '__main__':
    main()
