#!/usr/bin/python
# -*- encoding:utf-8 -*-

"""
Обработка pcap файла с получением на вызходе суммарной статистики
по количеству переданных пакетов и байт в секунду.
Для работы требует модуль dpkt, достуаный через pip.
В качестве первого аргумента коммандной строки требует имя
файла для обработки, результат записывается в текущий каталог в
файл с таким же именем, но расширением csv.

- tps-tcp - TRAFFIC PER SECOND ONLY FOR TCP PACKETS
"""

import dpkt
import sys
from os import path

def run(pcapfile):
    # открываем файл с данными - первый параметр коммандной строки
    infile  = open(pcapfile,'rb')
    # открываем для записи файл для сохранения статистики
    # получаем имя 1-ого файла без расширения и добавляем .csv
    outfileName = path.splitext(path.basename(pcapfile))[0]+'_tps-tcp.csv'
    outfile = open(outfileName,'w')

    # заголовки столбцов данных
    # outfile.write('time,packetsCount,bytesCount\n')

    # инициализаия счётчиков
    time = 0
    #packetsCount = 0
    bytesCount = 0

    for ts, buf in dpkt.pcap.Reader(infile):
        # если со времени последнего пакета прошла секунда:
        # обнуляем счётчики и записываем в файл статистику за последнюю секунду
        if ts - time > 1 :
            outfile.write(str(bytesCount)+'\n')
            time = ts
            #packetsCount = 0
            bytesCount = 0

        eth = dpkt.ethernet.Ethernet(buf)
        if( len(eth.data) > 0 and (eth.type == dpkt.ethernet.ETH_TYPE_IP) ):
            ip = eth.data
            if( len(ip.data) > 0 and (ip.p == dpkt.ip.IP_PROTO_TCP) ):
                bytesCount = bytesCount + len(buf)

    infile.close()
    outfile.close()
    return outfileName
