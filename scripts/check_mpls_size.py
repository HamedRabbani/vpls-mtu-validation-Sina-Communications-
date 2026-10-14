
from pathlib import Path
from scapy.all import rdpcap
from scapy.contrib.mpls import MPLS

pcap_path = Path("data/VPLS_PE(cisco)_PE(cisco).pcapng")
packets = rdpcap(str(pcap_path))

mpls_packets = [p for p in packets if p.haslayer(MPLS)]

print(f"Total packets: {len(packets)}")
print(f"MPLS packets: {len(mpls_packets)}")
print(f"Largest captured MPLS packet: {max(len(p) for p in mpls_packets)} bytes")
