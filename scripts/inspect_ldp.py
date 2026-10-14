import sys
from pathlib import Path

from scapy.all import TCP, rdpcap


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PCAP_PATH = (
    PROJECT_ROOT
    / "data"
    / "VPLS_PE(cisco)_PE(cisco).pcapng"
)

MAX_PACKETS = 5


def main() -> None:
    if not PCAP_PATH.is_file():
        raise FileNotFoundError(f"PCAP file not found: {PCAP_PATH}")

    packets = rdpcap(str(PCAP_PATH))

    matched = 0

    for number, packet in enumerate(packets, start=1):
        if TCP not in packet:
            continue

        tcp = packet[TCP]

        if tcp.sport != 646 and tcp.dport != 646:
            continue

        matched += 1

        print(f"\n{'=' * 60}")
        print(f"Packet number: {number}")
        print(f"Source port: {tcp.sport}")
        print(f"Destination port: {tcp.dport}")
        print(f"TCP flags: {tcp.flags}")
        print(f"Captured length: {len(packet)}")
        print(f"Summary: {packet.summary()}")

        # Display only a small sample to avoid excessive output.
        packet.show()

        if matched >= MAX_PACKETS:
            break

    print(f"\nTCP/646 packets inspected: {matched}")


if __name__ == "__main__":
    main()