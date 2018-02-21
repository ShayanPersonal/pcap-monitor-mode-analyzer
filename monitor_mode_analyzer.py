import time
import os
import sys

# For Python 3 and pcapng support, use scapy 2.4.0 or newer. 
# Install latest version from the git repo https://github.com/secdev/scapy
from scapy.all import *
import matplotlib.pyplot as plt

if len(sys.argv) < 3:
    exit("Usage: 'python {} pcap_filename timestep'".format(sys.argv[0]))

# Packet capture file to read from. Scapy 2.4 supports both pcap and pcapng. Otherwise use pcap only.
filename = sys.argv[1]

# x-axis temporal resolution used during graphing.
timestep = float(sys.argv[2])

# rdpcap comes from scapy and loads in our pcap or pcapng file
packets = rdpcap(filename)

start_time = packets[0].time
end_time = packets[-1].time

objects = ["packet_count", "bits", "unique_macs", "beacon_frames", "probe_responses", "acks", "block_acks", "block_ack_requests", 
            "request_to_send", "clear_to_send"]

list_length = int((end_time - start_time) // timestep + 1)
statistics = [dict(zip(objects, [0 for _ in objects]))
                for _ in range(list_length)]

mac_tracker = [set() for _ in statistics]

for packet in packets:
    index = int((packet.time - start_time) // timestep)
    statistics[index]["packet_count"] += 1
    statistics[index]["bits"] += packet.len
    # We use packet.version to check if packet was corrupts
    if RadioTap in packet and packet.version == 0:
        mac_tracker[index].add(packet.addr2)

        # Management type
        if packet.type == 0:
            if packet.subtype == 5:
                statistics[index]["probe_responses"] += 1
            if packet.subtype == 8:
                statistics[index]["beacon_frames"] += 1

        # Control type
        if packet.type == 1:
            if packet.subtype == 8:
                statistics[index]["block_ack_requests"] += 1
            if packet.subtype == 9:
                statistics[index]["block_acks"] += 1
            if packet.subtype == 12:
                statistics[index]["request_to_send"] += 1
            if packet.subtype == 12:
                statistics[index]["clear_to_send"] += 1
            if packet.subtype == 13:
                statistics[index]["acks"] += 1

for i, mac_counts in enumerate(statistics):
    mac_counts["unique_macs"] = len(mac_tracker[i])

if not os.path.isdir("figures"):
    os.mkdir("figures")

t = str(int(time.time()))[3:]
subdir = "{}_{}".format(filename, t)
os.mkdir("figures/" + subdir)

for obj in objects:
    plt.title(obj)
    plt.xlabel("time (seconds)")
    plt.ylabel(obj + " per second")
    plt.plot([i * timestep for i, _ in enumerate(statistics)], [y[obj] for y in statistics])
    plt.savefig("figures/{}/{}.png".format(subdir, obj))
    plt.clf()
