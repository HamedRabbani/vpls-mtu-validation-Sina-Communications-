from pathlib import Path

import pytest
from scapy.all import TCP, rdpcap, load_contrib
from scapy.contrib.bgp import BGPUpdate


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PCAP_PATH = PROJECT_ROOT / "data" / "VPLS_PE(cisco)_PE(cisco).pcapng"

BGP_PORT = 179
EXPECTED_MTU = 1500
LAYER2_INFO_SUBTYPE = 0x0A


@pytest.fixture(scope="module")
def pcap_packets():
    if not PCAP_PATH.is_file():
        pytest.fail(f"PCAP file not found: {PCAP_PATH}")

    load_contrib("bgp")
    return rdpcap(str(PCAP_PATH))


def extract_layer2_mtu(packet):
    """Extract MTU values from Layer2 Info Extended Communities."""
    mtus = []

    update = packet.getlayer(BGPUpdate)
    if update is None:
        return mtus

    for path_attr in getattr(update, "path_attr", []) or []:
        if getattr(path_attr, "type_code", None) != 16:
            continue

        # Scapy stores Extended Communities inside path_attr.attribute.
        attribute = getattr(path_attr, "attribute", None)
        communities = getattr(attribute, "extended_communities", []) or []

        for community in communities:
            subtype = getattr(community, "type_low", None)

            # Scapy may expose the subtype as an integer or a display string.
            is_layer2_info = (
                subtype == LAYER2_INFO_SUBTYPE
                or str(subtype) == "Layer2 Info Extended Community"
            )

            if not is_layer2_info:
                continue

            value = getattr(community, "value", None)
            if value is None:
                continue

            raw_value = getattr(value, "load", None)

            if raw_value is None:
                try:
                    raw_value = bytes(value)
                except (TypeError, ValueError):
                    continue

            if not isinstance(raw_value, bytes) or len(raw_value) != 6:
                continue

            # Value layout: Encapsulation (1), Control Flags (1),
            # Layer-2 MTU (2), Reserved (2).
            mtu = int.from_bytes(raw_value[2:4], byteorder="big")

            if mtu > 0:
                mtus.append(mtu)

    return mtus


def test_vpls_signaled_mtu(pcap_packets):
    """Verify that the PCAP contains a BGP-signaled Layer-2 MTU of 1500."""
    bgp_packets = [
        packet
        for packet in pcap_packets
        if packet.haslayer(TCP)
        and (
            packet[TCP].sport == BGP_PORT
            or packet[TCP].dport == BGP_PORT
        )
    ]

    assert bgp_packets, "No BGP packets found in the PCAP."

    bgp_updates = [
        packet
        for packet in bgp_packets
        if packet.haslayer(BGPUpdate)
    ]

    assert bgp_updates, "No parsed BGP UPDATE messages found."

    advertised_mtus = []

    for packet in bgp_updates:
        advertised_mtus.extend(extract_layer2_mtu(packet))

    assert advertised_mtus, (
        "No Layer2 Info Extended Community MTU values found. "
        "Check the parsed BGP UPDATE attributes."
    )

    print(f"Advertised Layer-2 MTU values: {sorted(set(advertised_mtus))}")

    assert EXPECTED_MTU in advertised_mtus, (
        f"Expected MTU {EXPECTED_MTU}; found {sorted(set(advertised_mtus))}."
    )

