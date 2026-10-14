from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, UDP, Ether, rdpcap
from scapy.contrib.mpls import MPLS


@dataclass(frozen=True)
class PacketInfo:
    """A compact representation of a captured packet."""

    number: int
    capture_length: int
    layers: str
    has_mpls: bool
    mpls_labels: tuple[int, ...]
    ip_length: int | None
    ip_source: str | None
    ip_destination: str | None
    transport_protocol: str | None
    source_port: int | None
    destination_port: int | None


@dataclass(frozen=True)
class CaptureReport:
    """Summary of a PCAP capture."""

    file_path: str
    total_packets: int
    layer_counts: dict[str, int]
    mpls_packets: int
    ip_packets: int
    udp_646_packets: int
    tcp_646_packets: int
    largest_ip_length: int | None
    largest_capture_length: int | None
    largest_packets: tuple[PacketInfo, ...]
    control_plane_samples: tuple[PacketInfo, ...]


def _extract_packet_info(packet: Any, number: int) -> PacketInfo:
    """Extract relevant fields without modifying the original packet."""

    has_mpls = MPLS in packet
    labels: list[int] = []

    if has_mpls:
        for layer in packet.layers():
            if layer.__name__ == "MPLS":
                labels.append(int(packet[layer].label))

    ip_length: int | None = None
    ip_source: str | None = None
    ip_destination: str | None = None

    if IP in packet:
        ip_length = packet[IP].len
        ip_source = packet[IP].src
        ip_destination = packet[IP].dst

    transport_protocol: str | None = None
    source_port: int | None = None
    destination_port: int | None = None

    if TCP in packet:
        transport_protocol = "TCP"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)

    elif UDP in packet:
        transport_protocol = "UDP"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)

    return PacketInfo(
        number=number,
        capture_length=len(packet),
        layers=packet.summary(),
        has_mpls=has_mpls,
        mpls_labels=tuple(labels),
        ip_length=ip_length,
        ip_source=ip_source,
        ip_destination=ip_destination,
        transport_protocol=transport_protocol,
        source_port=source_port,
        destination_port=destination_port,
    )


def analyze_pcap(
    file_path: str | Path,
    *,
    largest_limit: int = 10,
    control_plane_limit: int = 10,
) -> CaptureReport:
    """
    Analyze a PCAP/PCAPNG file and return a structured summary.

    This function describes observed traffic. It does not determine
    whether the configured VPLS service MTU is correct.
    """

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    if largest_limit < 0 or control_plane_limit < 0:
        raise ValueError("Output limits must be non-negative.")

    # Read the capture once.
    packets = rdpcap(str(path))

    layer_counts: Counter[str] = Counter()
    packet_infos: list[PacketInfo] = []

    mpls_packets = 0
    ip_packets = 0
    udp_646_packets = 0
    tcp_646_packets = 0

    for number, packet in enumerate(packets, start=1):
        info = _extract_packet_info(packet, number)
        packet_infos.append(info)

        # Count each distinct layer type present in this packet.
        seen_layers = {
            layer.__name__
            for layer in packet.layers()
        }
        layer_counts.update(seen_layers)

        if info.has_mpls:
            mpls_packets += 1

        if IP in packet:
            ip_packets += 1

        if info.transport_protocol == "UDP":
            if info.source_port == 646 or info.destination_port == 646:
                udp_646_packets += 1

        if info.transport_protocol == "TCP":
            if info.source_port == 646 or info.destination_port == 646:
                tcp_646_packets += 1

    ip_packets_with_length = [
        info
        for info in packet_infos
        if info.ip_length is not None
    ]

    largest_packets = sorted(
        ip_packets_with_length,
        key=lambda info: info.ip_length or 0,
        reverse=True,
    )[:largest_limit]

    control_plane_samples = tuple(
        info
        for info in packet_infos
        if (
            info.transport_protocol in {"TCP", "UDP"}
            and (
                info.source_port == 646
                or info.destination_port == 646
            )
        )
    )[:control_plane_limit]

    largest_ip_length = (
        max(info.ip_length for info in ip_packets_with_length
            if info.ip_length is not None)
        if ip_packets_with_length
        else None
    )

    largest_capture_length = (
        max(info.capture_length for info in packet_infos)
        if packet_infos
        else None
    )

    return CaptureReport(
        file_path=str(path),
        total_packets=len(packets),
        layer_counts=dict(layer_counts),
        mpls_packets=mpls_packets,
        ip_packets=ip_packets,
        udp_646_packets=udp_646_packets,
        tcp_646_packets=tcp_646_packets,
        largest_ip_length=largest_ip_length,
        largest_capture_length=largest_capture_length,
        largest_packets=tuple(largest_packets),
        control_plane_samples=control_plane_samples,
    )