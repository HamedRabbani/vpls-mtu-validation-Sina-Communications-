from __future__ import annotations

import argparse
import json
import socket
from collections import defaultdict
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, rdpcap


# BGP constants
BGP_PORT = 179
BGP_HEADER_LENGTH = 19
BGP_MAX_MESSAGE_LENGTH = 4096
BGP_UPDATE = 2

AFI_L2VPN = 25
SAFI_VPLS = 65

MP_REACH_NLRI = 14
EXTENDED_COMMUNITIES = 16

LAYER2_INFO_TYPE = 0x80
LAYER2_INFO_SUBTYPE = 0x0A
ROUTE_TARGET_SUBTYPE = 0x02

VPLS_NLRI_PAYLOAD_LENGTH = 17


def decode_ip(data: bytes) -> str:
    """Decode an IPv4 or IPv6 address."""

    if len(data) == 4:
        return socket.inet_ntoa(data)

    if len(data) == 16:
        return socket.inet_ntop(socket.AF_INET6, data)

    return data.hex()


def decode_rd(data: bytes) -> str:
    """Decode an 8-byte Route Distinguisher."""

    if len(data) != 8:
        raise ValueError(f"Invalid RD length: {len(data)}")

    rd_type = int.from_bytes(data[:2], "big")

    if rd_type == 0:
        return (
            f"{int.from_bytes(data[2:4], 'big')}:"
            f"{int.from_bytes(data[4:8], 'big')}"
        )

    if rd_type == 1:
        return (
            f"{socket.inet_ntoa(data[2:6])}:"
            f"{int.from_bytes(data[6:8], 'big')}"
        )

    if rd_type == 2:
        return (
            f"{int.from_bytes(data[2:6], 'big')}:"
            f"{int.from_bytes(data[6:8], 'big')}"
        )

    return f"unknown-type-{rd_type}:{data[2:].hex()}"


def decode_route_target(data: bytes) -> str | None:
    """Decode supported Route Target extended communities."""

    if len(data) != 8 or data[1] != ROUTE_TARGET_SUBTYPE:
        return None

    community_type = data[0] & 0x3F

    if community_type == 0:
        administrator = int.from_bytes(data[2:4], "big")
        assigned = int.from_bytes(data[4:8], "big")
        return f"{administrator}:{assigned}"

    if community_type == 1:
        administrator = socket.inet_ntoa(data[2:6])
        assigned = int.from_bytes(data[6:8], "big")
        return f"{administrator}:{assigned}"

    if community_type == 2:
        administrator = int.from_bytes(data[2:6], "big")
        assigned = int.from_bytes(data[6:8], "big")
        return f"{administrator}:{assigned}"

    return None


def decode_extended_communities(data: bytes) -> dict[str, Any]:
    """Extract Route Targets and Layer-2 MTU values."""

    result: dict[str, Any] = {
        "route_targets": [],
        "layer2_mtu": [],
        "raw": [],
    }

    if len(data) % 8:
        result["parse_warning"] = (
            "Extended Communities length is not divisible by 8"
        )

    for offset in range(0, len(data) - len(data) % 8, 8):
        community = data[offset:offset + 8]
        result["raw"].append(community.hex())

        route_target = decode_route_target(community)

        if route_target is not None:
            result["route_targets"].append(route_target)

        if (
            community[0] == LAYER2_INFO_TYPE
            and community[1] == LAYER2_INFO_SUBTYPE
        ):
            result["layer2_mtu"].append({
                "mtu": int.from_bytes(community[4:6], "big"),
                "raw": community.hex(),
            })

    return result


def decode_vpls_nlri(data: bytes) -> dict[str, Any]:
    """
    Decode a VPLS NLRI.

    Supports the one-byte bit-length representation used by the
    current unit test and the two-byte length representation observed
    in the supplied capture.
    """

    if not data:
        raise ValueError("VPLS NLRI is empty")

    if data[0] == 0:
        if len(data) < 2:
            raise ValueError("Incomplete two-byte NLRI length")

        payload_length = int.from_bytes(data[:2], "big")
        length_encoding = "two-byte"

        if payload_length != VPLS_NLRI_PAYLOAD_LENGTH:
            raise ValueError(
                f"Unsupported VPLS payload length: {payload_length}"
            )

        header_length = 2
        length_bits = payload_length * 8

    else:
        length_bits = data[0]

        if length_bits % 8:
            raise ValueError(
                f"NLRI length is not byte-aligned: {length_bits} bits"
            )

        payload_length = length_bits // 8
        length_encoding = "one-byte-bits"

        if payload_length != VPLS_NLRI_PAYLOAD_LENGTH:
            raise ValueError(
                f"Unsupported VPLS payload length: {payload_length}"
            )

        header_length = 1

    expected_length = header_length + payload_length

    if len(data) < expected_length:
        raise ValueError(
            f"Truncated NLRI: expected {expected_length} bytes, "
            f"received {len(data)}"
        )

    payload = data[header_length:expected_length]

    return {
        "length_bits": length_bits,
        "length_bytes": payload_length,
        "length_encoding": length_encoding,
        "route_distinguisher": decode_rd(payload[:8]),
        "ve_id": int.from_bytes(payload[8:10], "big"),
        "ve_block_offset": int.from_bytes(payload[10:12], "big"),
        "ve_block_size": int.from_bytes(payload[12:14], "big"),
        "label_base": int.from_bytes(payload[14:17], "big") >> 4,
        "raw": data[:expected_length].hex(),
    }


def parse_mp_reach_nlri(data: bytes) -> dict[str, Any]:
    """Parse MP_REACH_NLRI and decode VPLS routes."""

    if len(data) < 4:
        raise ValueError("MP_REACH_NLRI is too short")

    afi = int.from_bytes(data[:2], "big")
    safi = data[2]
    next_hop_length = data[3]

    next_hop_start = 4
    next_hop_end = next_hop_start + next_hop_length

    if len(data) < next_hop_end + 1:
        raise ValueError("Incomplete MP_REACH_NLRI next-hop field")

    result: dict[str, Any] = {
        "afi": afi,
        "safi": safi,
        "next_hop_length": next_hop_length,
        "next_hop": decode_ip(data[next_hop_start:next_hop_end]),
        "reserved": data[next_hop_end],
        "nlri": [],
        "raw_nlri": data[next_hop_end + 1:].hex(),
    }

    if afi != AFI_L2VPN or safi != SAFI_VPLS:
        return result

    nlri_data = data[next_hop_end + 1:]
    offset = 0
    errors: list[str] = []

    while offset < len(nlri_data):
        remaining = len(nlri_data) - offset

        # The capture may use a two-byte length field (00 11).
        if nlri_data[offset] == 0:
            if remaining < 2:
                errors.append("Incomplete two-byte NLRI length")
                break

            payload_length = int.from_bytes(
                nlri_data[offset:offset + 2], "big"
            )

            if payload_length != VPLS_NLRI_PAYLOAD_LENGTH:
                errors.append(
                    f"Unsupported two-byte NLRI length: {payload_length}"
                )
                break

            total_length = 2 + payload_length

        else:
            # Compatibility with the one-byte bit-length test fixture.
            length_bits = nlri_data[offset]

            if length_bits % 8:
                errors.append(
                    f"Invalid NLRI length at offset {offset}: "
                    f"{length_bits} bits"
                )
                break

            payload_length = length_bits // 8

            if payload_length != VPLS_NLRI_PAYLOAD_LENGTH:
                errors.append(
                    f"Unsupported one-byte NLRI length: {length_bits} bits"
                )
                break

            total_length = 1 + payload_length

        if remaining < total_length:
            errors.append(
                f"Truncated NLRI at offset {offset}: "
                f"expected {total_length} bytes, got {remaining}"
            )
            break

        raw_nlri = nlri_data[offset:offset + total_length]

        try:
            result["nlri"].append(decode_vpls_nlri(raw_nlri))
        except ValueError as exc:
            errors.append(str(exc))
            break

        offset += total_length

    if errors:
        result["parse_errors"] = errors

    return result


def extract_tcp_streams(pcap_path: Path) -> dict[str, Any]:
    """Extract TCP payloads involving BGP port 179."""

    packets = rdpcap(str(pcap_path))
    streams: dict[tuple, list[dict[str, Any]]] = defaultdict(list)

    for packet_number, packet in enumerate(packets, start=1):
        if IP not in packet or TCP not in packet:
            continue

        tcp = packet[TCP]

        if tcp.sport != BGP_PORT and tcp.dport != BGP_PORT:
            continue

        payload = bytes(tcp.payload)

        if not payload:
            continue

        source = (packet[IP].src, int(tcp.sport))
        destination = (packet[IP].dst, int(tcp.dport))

        streams[(source, destination)].append({
            "seq": int(tcp.seq),
            "data": payload,
            "packet_number": packet_number,
        })

    return {"packets": packets, "streams": streams}


def reassemble_stream(segments: list[dict[str, Any]]) -> bytes:
    """Perform basic TCP sequence-based reassembly."""

    output = bytearray()
    expected_seq: int | None = None

    for segment in sorted(segments, key=lambda item: item["seq"]):
        seq = segment["seq"]
        data = segment["data"]

        if not data:
            continue

        if expected_seq is None or seq > expected_seq:
            expected_seq = seq

        if seq < expected_seq:
            overlap = expected_seq - seq

            if overlap >= len(data):
                continue

            data = data[overlap:]

        output.extend(data)
        expected_seq += len(data)

    return bytes(output)


def extract_bgp_messages(stream: bytes) -> list[bytes]:
    """Extract complete BGP messages from a TCP stream."""

    messages = []
    offset = 0
    marker = b"\xff" * 16

    while offset + BGP_HEADER_LENGTH <= len(stream):
        if stream[offset:offset + 16] != marker:
            next_marker = stream.find(marker, offset + 1)

            if next_marker == -1:
                break

            offset = next_marker
            continue

        length = int.from_bytes(stream[offset + 16:offset + 18], "big")

        if not BGP_HEADER_LENGTH <= length <= BGP_MAX_MESSAGE_LENGTH:
            offset += 1
            continue

        if offset + length > len(stream):
            break

        messages.append(stream[offset:offset + length])
        offset += length

    return messages


def parse_path_attributes(data: bytes) -> list[dict[str, Any]]:
    """Parse BGP Path Attributes and decode supported attributes."""

    attributes = []
    offset = 0

    while offset < len(data):
        if len(data) - offset < 3:
            attributes.append({
                "parse_error": "Incomplete Path Attribute header",
                "raw": data[offset:].hex(),
            })
            break

        flags = data[offset]
        attribute_type = data[offset + 1]
        offset += 2

        if flags & 0x10:
            if len(data) - offset < 2:
                attributes.append({
                    "parse_error": "Incomplete extended attribute length",
                    "type": attribute_type,
                })
                break

            attribute_length = int.from_bytes(
                data[offset:offset + 2], "big"
            )
            offset += 2
        else:
            attribute_length = data[offset]
            offset += 1

        end = offset + attribute_length

        if end > len(data):
            attributes.append({
                "type": attribute_type,
                "flags": flags,
                "parse_error": "Path Attribute exceeds UPDATE boundary",
                "raw": data[offset:].hex(),
            })
            break

        value = data[offset:end]
        offset = end

        attribute: dict[str, Any] = {
            "type": attribute_type,
            "flags": flags,
            "length": attribute_length,
            "raw": value.hex(),
            "decoded": {},
        }

        try:
            if attribute_type == MP_REACH_NLRI:
                attribute["decoded"] = parse_mp_reach_nlri(value)

            elif attribute_type == EXTENDED_COMMUNITIES:
                attribute["decoded"] = decode_extended_communities(value)

        except (ValueError, IndexError) as exc:
            attribute["parse_error"] = str(exc)

        attributes.append(attribute)

    return attributes


def parse_bgp_update(message: bytes) -> dict[str, Any] | None:
    """Parse a BGP UPDATE message."""

    if len(message) < BGP_HEADER_LENGTH:
        return None

    if message[18] != BGP_UPDATE:
        return None

    declared_length = int.from_bytes(message[16:18], "big")

    if declared_length != len(message):
        return None

    data = message[BGP_HEADER_LENGTH:]

    if len(data) < 4:
        return None

    withdrawn_length = int.from_bytes(data[:2], "big")
    offset = 2 + withdrawn_length

    if offset + 2 > len(data):
        return None

    attribute_length = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2

    attribute_end = offset + attribute_length

    if attribute_end > len(data):
        return None

    attributes = parse_path_attributes(data[offset:attribute_end])

    return {
        "path_attributes": attributes,
        "withdrawn_routes_length": withdrawn_length,
        "path_attributes_length": attribute_length,
        "nlri_length": len(data) - attribute_end,
    }


def analyze_pcap(pcap_path: Path) -> list[dict[str, Any]]:
    """Analyze BGP UPDATE messages in a PCAP/PCAPNG file."""

    stream_data = extract_tcp_streams(pcap_path)
    results = []
    total_messages = 0
    invalid_updates = 0

    for (source, destination), segments in stream_data["streams"].items():
        stream = reassemble_stream(segments)

        for message in extract_bgp_messages(stream):
            total_messages += 1
            update = parse_bgp_update(message)

            if update is None:
                invalid_updates += 1
                continue

            update["source"] = f"{source[0]}:{source[1]}"
            update["destination"] = f"{destination[0]}:{destination[1]}"

            errors = []

            for attribute in update["path_attributes"]:
                if attribute.get("parse_error"):
                    errors.append(attribute["parse_error"])

                decoded = attribute.get("decoded", {})

                if isinstance(decoded, dict):
                    errors.extend(decoded.get("parse_errors", []))

            update["parse_errors"] = errors
            results.append(update)

    print(f"Packets read: {len(stream_data['packets'])}")
    print(f"Directed TCP streams: {len(stream_data['streams'])}")
    print(f"BGP messages extracted: {total_messages}")
    print(f"BGP UPDATE messages parsed: {len(results)}")
    print(f"Invalid or unparsed messages: {invalid_updates}")

    return results


def build_report(updates: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a JSON report containing VPLS signaling information."""

    vpls_updates = []

    for update in updates:
        route_targets = []
        mtu_values = []
        nlri_routes = []
        parse_errors = list(update.get("parse_errors", []))
        parse_warnings = []

        for attribute in update.get("path_attributes", []):
            if attribute.get("parse_error"):
                continue

            decoded = attribute.get("decoded", {})
            if not isinstance(decoded, dict):
                continue

            if attribute.get("type") == EXTENDED_COMMUNITIES:
                route_targets.extend(decoded.get("route_targets", []))
                mtu_values.extend(
                    item["mtu"]
                    for item in decoded.get("layer2_mtu", [])
                )

                if decoded.get("parse_warning"):
                    parse_warnings.append(decoded["parse_warning"])

            elif attribute.get("type") == MP_REACH_NLRI:
                nlri_routes.extend(decoded.get("nlri", []))
                parse_errors.extend(decoded.get("parse_errors", []))

        if route_targets or mtu_values or nlri_routes or parse_errors or parse_warnings:
            vpls_updates.append({
                "source": update.get("source", ""),
                "destination": update.get("destination", ""),
                "route_targets": sorted(set(route_targets)),
                "advertised_mtu_values": sorted(set(mtu_values)),
                "nlri_routes": nlri_routes,
                "parse_errors": parse_errors,
                "parse_warnings": parse_warnings,
            })

    return {
        "summary": {
            "bgp_updates": len(updates),
            "vpls_related_updates": len(vpls_updates),
            "advertised_mtu_values": sorted({
                mtu
                for update in vpls_updates
                for mtu in update["advertised_mtu_values"]
            }),
            "updates_with_parse_errors": sum(
                bool(update["parse_errors"]) for update in vpls_updates
            ),
        },
        "vpls_updates": vpls_updates,
        "limitations": [
            "TCP reassembly is basic and may not handle every retransmission or overlap.",
            "Capture gaps may cause BGP messages to be missed.",
            "Only IPv4/TCP traffic involving port 179 is analyzed.",
            "The parser supports the NLRI length encodings described in its decoder; verify them against the capture and protocol specification.",
            "Advertised Layer-2 MTU does not prove the operational service MTU.",
            "Confirm the operational MTU using both PE configurations and service state.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect BGP VPLS signaling and advertised MTU."
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default="data/VPLS_PE(cisco)_PE(cisco).pcapng",
        help="Input PCAP or PCAPNG file",
    )
    parser.add_argument(
        "--output",
        default="reports/bgp_vpls_mtu.json",
        help="Output JSON report",
    )

    args = parser.parse_args()
    pcap_path = Path(args.pcap)
    output_path = Path(args.output)

    if not pcap_path.is_file():
        raise SystemExit(f"PCAP file not found: {pcap_path}")

    try:
        updates = analyze_pcap(pcap_path)
        report = build_report(updates)
    except Exception as exc:
        raise SystemExit(
            f"Failed to analyze PCAP: {type(exc).__name__}: {exc}"
        ) from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Report saved to: {output_path}")
    print(json.dumps(report["summary"], indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()