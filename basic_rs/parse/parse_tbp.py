#!/usr/bin/python
# -*- encoding:utf-8 -*-

"""
Для работы требует модуль dpkt, достуаный через pip.
В качестве первого аргумента коммандной строки требует имя
файла для обработки, результат записывается в текущий каталог в
файл с таким же именем, но расширением csv.

РАССЧЕТ ВРЕМЕНИ МЕЖДУ ПАКЕТАМИ
- tbp - TIME BETWEEN PACKETS
"""

import dpkt
import sys
from os import path

def run(pcapfile):
    # открываем файл с данными - первый параметр коммандной строки
    infile  = open(pcapfile,'rb')
    # открываем для записи файл для сохранения статистики
    # получаем имя 1-ого файла без расширения и добавляем .csv
    outfileName = path.splitext(path.basename(pcapfile))[0]+'_tbp.csv'
    outfile = open(outfileName,'w')

    # заголовки столбцов данных
    # outfile.write('deltaTime\n')

    # инициализаия счётчиков
    deltaTime = 0
    previousTime = 0

    for ts, buf in dpkt.pcap.Reader(infile):
        # print "ts - ", ts

        if previousTime > 0:
            deltaTime = ts - previousTime
            previousTime = ts
            outfile.write(str(deltaTime)+'\n')
        else:
            outfile.write(str(0)+'\n')
            previousTime = ts

    infile.close()
    outfile.close()
    return outfileName
