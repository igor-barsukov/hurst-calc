import argparse
import os
from basic_rs import basic_rs
from basic_rs.parse import parse_tps
from basic_rs.parse import parse_tps_tcp
from basic_rs.parse import parse_tps_tcp_decisec
from basic_rs.parse import parse_tbp
from basic_rs.parse import parse_ncps

"""
Usage examples:

python -m basic_rs stat --file=merged-2017-11-27-10-02_tps.csv
python -m basic_rs stat --dir=D:/Aspirantura/nsl-kdd-hurst-calc
python -m basic_rs pcap --pcapfile=normal_traffic_5min --parsemode=tps
"""

def main():
    # log_file = open("logger.log","w")
    # sys.stdout = log_file
    parser = argparse.ArgumentParser(description = 'Test argparse')

    subparsers = parser.add_subparsers(help='Choose mode', dest='mode')
    # Stat file mode
    stat_parser = subparsers.add_parser("stat", help="Process stat file")
    stat_parser.add_argument("--file", type=str, help="Stat file name")
    stat_parser.add_argument("--dir", type=str, help="Directory containing stat files")
    # Pcap mode
    pcap_parser = subparsers.add_parser("pcap", help="Process pcap file")
    pcap_parser.add_argument("--pcapfile", type=str, help="Pcap file name")
    pcap_parser.add_argument("--parsemode",
                            choices=["tps", "tps-tcp", "tps-tcp-decisec", "tbp", "ncps"],
                            required=True, type=str, help="Parsing mode")

    args = parser.parse_args()
    if args.mode == "stat":
        if args.file is not None:
            print('Processing stat file - ', args.file)
            basic_rs.run(args.file)
        elif args.dir is not None:
            print('Processing dir with stat files - ', args.dir)
            for file in os.listdir(args.dir):
                if file.endswith(".csv"):
                    print("Processing file - ", file)
                    basic_rs.run(file)
    elif args.mode == "pcap":
        pcapfile = args.pcapfile
        parsemode = args.parsemode
        print('Processing pcap file - ', pcapfile)
        print('Parse mode - ', parsemode)

        if parsemode == "tps":
            file = parse_tps.run(pcapfile)
        elif parsemode == "tps-tcp":
            file = parse_tps_tcp.run(pcapfile)
        elif parsemode == "tps-tcp-decisec":
            file = parse_tps_tcp_decisec.run(pcapfile)
        elif parsemode == "tbp":
            file = parse_tbp.run(pcapfile)
        elif parsemode == "ncps":
            file = parse_ncps.run(pcapfile)
        else:
            file = parse_tps.run(pcapfile) # default mode

        print('Generated file - ', file)
        basic_rs.run(file)
    else:
        print('Undefined mode')

    # log_file.close()

if __name__ == '__main__':
    main()
