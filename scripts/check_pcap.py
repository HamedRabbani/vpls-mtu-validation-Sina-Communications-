import logging
import sys
from pathlib import Path

# Add the project's src directory to the import path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from vpls_mtu_checker.analyzer import analyze_pcap


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)

PCAP_PATH = (
    PROJECT_ROOT
    / "data"
    / "VPLS_PE(cisco)_PE(cisco).pcapng"
)


def print_report(report) -> None:
    """Print the main findings from a PCAP analysis."""

    print("\n=== PCAP Overview ===")
    print(f"File: {report.file_path}")
    print(f"Total packets: {report.total_packets}")
    print(f"Packets containing MPLS: {report.mpls_packets}")
    print(f"Packets containing IPv4: {report.ip_packets}")

    print("\n=== Layer Counts ===")
    for layer_name, count in sorted(report.layer_counts.items()):
        print(f"{layer_name}: {count}")

    print("\n=== Port 646 Traffic ===")
    print(f"UDP packets involving port 646: {report.udp_646_packets}")
    print(f"TCP packets involving port 646: {report.tcp_646_packets}")

    print("\n=== Largest Observed Lengths ===")
    print(f"Largest IPv4 packet length: {report.largest_ip_length}")
    print(f"Largest captured packet length: {report.largest_capture_length}")

    print("\n=== Largest Packets Containing IPv4 ===")
    for packet in report.largest_packets:
        print(
            f"Packet #{packet.number}: "
            f"IP length={packet.ip_length}, "
            f"capture length={packet.capture_length}, "
            f"MPLS={packet.has_mpls}, "
            f"layers={packet.layers}"
        )

    print("\n=== Selected Packets Involving Port 646 ===")
    if not report.control_plane_samples:
        print("No TCP/UDP packets involving port 646 were found.")
    else:
        for packet in report.control_plane_samples:
            print(
                f"Packet #{packet.number}: "
                f"{packet.transport_protocol} "
                f"{packet.source_port} -> {packet.destination_port}, "
                f"length={packet.capture_length}, "
                f"layers={packet.layers}"
            )

    print("\n=== MTU Assessment ===")
    print(
        "This report describes observed packet sizes only. "
        "It does not establish whether the VPLS service MTU is 1500."
    )


def main() -> int:
    """Run the exploratory PCAP analysis."""

    try:
        report = analyze_pcap(PCAP_PATH)
    except (FileNotFoundError, ValueError, OSError) as exc:
        logging.error("%s", exc)
        return 1

    print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())