# hurst-calc

Utility intended to measure self-similarity of network traffic.
Calculates value of Hurst coefficient for specified data structure (stat file or raw traffic dumps file) using R/S analysis method.  

Allows to process two types of files:
- 'stat' mode  -  processing of separate text file (normally .csv) with selected traffic attribute or group of files in specified directory

  Usage:
  > python -m basic_rs stat --file=<stat-file.csv>
  or
  > python -m basic_rs stat --dir=<directory containing .csv stat files>

- 'pcap' mode  -  processing of raw pcap file. Consists of 2 stages:
    - selecting of specified traffic attribute from pcap file and generating text file with values of this attribute
    - processing of generated on previous step text file

    This mode allows to select next traffic attributes (parsemodes):
    - tps (traffic per second for all packets types)
    - tps-tcp (traffic per second only for TCP packets)
    - tps-tcp-decisec (traffic per 0.1 second only for TCP packets)
    - tbp (time between packets)
    - ncps (new connections per second)

  Usage:
  > python -m basic_rs pcap --pcapfile=<pcap-file.pcap> --parsemode=[tps, tps-tcp, tps-tcp-decisec, tbp, ncps]
