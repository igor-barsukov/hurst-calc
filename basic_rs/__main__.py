import argparse
from basic_rs import basic_rs
from basic_rs.parse import parse_tps

"""
Usage:

python -m basic_rs stat --file=merged-2017-11-27-10-02_tps.csv
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
    # Pcap mode
    pcap_parser = subparsers.add_parser("pcap", help="Process pcap file")
    pcap_parser.add_argument("--pcapfile", type=str, help="Pcap file name")
    pcap_parser.add_argument("--parsemode",
                            choices=["tps", "tps-tcp", "tps-tcp-decisec", "tbp", "ncps"],
                            required=True, type=str, help="Parsing mode")

    args = parser.parse_args()
    if args.mode == "stat":
        file = args.file
        print('Processing stat file - ', file)
        basic_rs.run(file)
    elif args.mode == "pcap":
        pcapfile = args.pcapfile
        parsemode = args.parsemode
        print('Processing pcap file - ', pcapfile)
        print('Parse mode - ', parsemode)

        if parsemode == "tps":
            file = parse_tps.run(pcapfile)
        elif parsemode == "tps-tcp":
            file = parse_tps-tcp.run(pcapfile)
        elif parsemode == "tps-tcp-decisec":
            file = parse_tps-tcp-decisec.run(pcapfile)
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
