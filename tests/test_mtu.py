from pathlib import Path

import pytest
from scapy.all import rdpcap
from scapy.contrib.mpls import MPLS

PCAP_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "VPLS_PE(cisco)_PE(cisco).pcapng"
)

EXPECTED_MTU = 1500


@pytest.fixture(scope="module")
def pcap_packets():
    assert PCAP_PATH.is_file(), f"PCAP file not found: {PCAP_PATH}"
    return rdpcap(str(PCAP_PATH))


def test_vpls_captured_packet_sizes(pcap_packets):
    mpls_packets = [
        packet for packet in pcap_packets
        if packet.haslayer(MPLS)
    ]

    assert mpls_packets, "No MPLS packets found in PCAP"

    packet_sizes = [len(packet) for packet in mpls_packets]
    largest_packet = max(packet_sizes)

    assert largest_packet <= EXPECTED_MTU, (
        f"Largest captured MPLS packet is {largest_packet} bytes; "
        f"limit is {EXPECTED_MTU} bytes"
    )