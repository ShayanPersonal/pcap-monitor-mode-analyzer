# pcap-monitor-mode-analyzer
This program was written for a graduate mobile computing course (CS284) at UCSB for analyzing network congestion.

This program takes a pcap capture performed in monitor mode as input and computes and graphs various wireless statistics of the file.
Statistics graphed per unit time include:
- Packet count
- Total bits encountered
- Unique transmitter MAC addresses encountered
- Beacon frames
- Probe response frames
- Ack frames
- Block ack frames
- Block ack request frames
- Request-to-send frames
- Clear-to-send frames

Example usage:
python monitor_mode_analyzer.py my_capture.pcap 1

Requirements:
- Python
- Scapy
- Matplotlib

For Python 3 and PCAPNG support you need Scapy 2.4.0 or newer. You will need to install the development version of Scapy at https://github.com/secdev/scapy.
