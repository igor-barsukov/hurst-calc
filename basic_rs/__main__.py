import argparse
from basic_rs import basic_rs
from basic_rs.parse import parse1_tps

def main():
    # log_file = open("logger.log","w")
    # sys.stdout = log_file
    parser = argparse.ArgumentParser(description = 'Test argparse')

    parser.add_argument("--mode", choices=["stat", "pcap"],
                        required=True, type=str, help="Processing mode")
    parser.add_argument("--file", type=str, help="Stat file name")
    parser.add_argument("--pcapfile", type=str, help="Pcap file name")

    args = parser.parse_args()
    mode = args.mode
    file = args.file
    pcapfile = args.pcapfile

    if mode == "stat":
        print('Processing stat file - ', file)
        basic_rs.run(file)
    elif mode == "pcap":
        print('Processing pcap file - ', pcapfile)
        file = parse1_tps.run(pcapfile)
        print('Generated file - ', file)
        basic_rs.run(file)
    else:
        print('Undefined mode')
    # log_file.close()

if __name__ == '__main__':
    main()
