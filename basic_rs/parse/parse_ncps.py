#!/usr/bin/python
# -*- encoding:utf-8 -*-

"""
Для работы требует модуль dpkt, достуаный через pip.
В качестве первого аргумента коммандной строки требует имя
файла для обработки, результат записывается в текущий каталог в
файл с таким же именем, но расширением csv.

РАССЧЕТ КОЛИЧЕСТВА НОВЫХ СОЕДИНЕНИЙ В СЕКУНДУ (число пакетов с флагом SYN)
- ncps - NEW CONNECTIONS PER SECOND
"""

### bkp
# fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
# rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
# psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
# urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
# ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
# cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0
# print ('fin_flag - {}, syn_flag - {}, rst_flag - {}, psh_flag - {}, ack_flag - {}, urg_flag - {}, ece_flag - {}, cwr_flag - {} at time - {}'.format(fin_flag, syn_flag, rst_flag, psh_flag, ack_flag, urg_flag, ece_flag, cwr_flag, ts))

import dpkt
import sys
from os import path

def run(pcapfile):
    # открываем файл с данными - первый параметр коммандной строки
    infile  = open(pcapfile,'rb')
    # открываем для записи файл для сохранения статистики
    # получаем имя 1-ого файла без расширения и добавляем .csv
    outfileName = path.splitext(path.basename(pcapfile))[0]+'_ncps.csv'
    outfile = open(outfileName,'w')

    # инициализаия счётчиков
    time = 0
    synPacketsCount = 0

    for ts, buf in dpkt.pcap.Reader(infile):
        if ts - time > 1:
            print('ts - ', ts)
            outfile.write(str(synPacketsCount)+'\n')
            time = ts
            synPacketsCount = 0

        eth = dpkt.ethernet.Ethernet(buf)
        if( len(eth.data) > 0 and (eth.type == dpkt.ethernet.ETH_TYPE_IP) ):
            ip = eth.data
            if( len(ip.data) > 0 and (ip.p == dpkt.ip.IP_PROTO_TCP) ):
                tcp = ip.data
                syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
                ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0

                if(syn_flag and not ack_flag):
                    # print('SYN')
                    # print('flags - ', tcp.flags)
                    synPacketsCount += 1

    infile.close()
    outfile.close()
    return outfileName
