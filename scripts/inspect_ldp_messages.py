from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import IP, TCP, rdpcap


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PCAP_PATH = (
    PROJECT_ROOT
    / "data"
    / "VPLS_PE(cisco)_PE(cisco).pcapng"
)

LDP_PORT = 646
MAX_SAMPLES = 15

MESSAGE_TYPES = {
    0x0001: "Notification",
    0x0100: "Hello",
    0x0200: "Initialization",
    0x0201: "KeepAlive",
    0x0300: "Address",
    0x0301: "Address Withdraw",
    0x0400: "Label Mapping",
    0x0401: "Label Request",
    0x0402: "Label Withdraw",
    0x0403: "Label Release",
    0x0404: "Label Abort Request",
}


def collect_tcp_streams(packets):
    """Collect TCP payload segments by directional connection."""

    streams = defaultdict(list)

    for packet_number, packet in enumerate(packets, start=1):
        if IP not in packet or TCP not in packet:
            continue

        tcp = packet[TCP]

        if tcp.sport != LDP_PORT and tcp.dport != LDP_PORT:
            continue

        payload = bytes(tcp.payload)

        if not payload:
            continue

        # TCP SYN consumes one sequence number.
        sequence = int(tcp.seq)

        if "S" in tcp.flags:
            sequence += 1

        flow = (
            packet[IP].src,
            int(tcp.sport),
            packet[IP].dst,
            int(tcp.dport),
        )

        streams[flow].append(
            (sequence, payload, packet_number)
        )

    return streams


def reassemble_tcp_segments(segments):
    """
    Reassemble contiguous TCP payload chunks.

    Retransmitted and overlapping bytes are not appended twice.
    Gaps produce separate chunks rather than fabricated data.
    """

    if not segments:
        return []

    segments = sorted(segments, key=lambda item: item[0])

    chunks = []

    current_start = segments[0][0]
    current_data = bytearray(segments[0][1])
    current_end = current_start + len(current_data)

    for sequence, payload, _packet_number in segments[1:]:
        segment_end = sequence + len(payload)

        if sequence > current_end:
            # A sequence gap means the stream is not contiguous.
            chunks.append(bytes(current_data))

            current_start = sequence
            current_data = bytearray(payload)
            current_end = segment_end
            continue

        # Trim bytes already covered by the assembled data.
        overlap = current_end - sequence

        if overlap < len(payload):
            new_data = payload[max(0, overlap):]
            current_data.extend(new_data)
            current_end += len(new_data)

    chunks.append(bytes(current_data))

    return chunks


def parse_ldp_pdu(data, offset):
    """
    Parse one complete LDP PDU.

    Returns None if the candidate is incomplete or invalid.
    """

    if offset + 10 > len(data):
        return None

    version = int.from_bytes(data[offset:offset + 2], "big")
    pdu_length = int.from_bytes(data[offset + 2:offset + 4], "big")

    if version != 1 or pdu_length < 6:
        return None

    total_length = 4 + pdu_length
    end = offset + total_length

    if end > len(data):
        return None

    ldp_identifier = data[offset + 4:offset + 8]
    label_space = int.from_bytes(
        data[offset + 8:offset + 10],
        "big",
    )

    messages = []
    cursor = offset + 10

    while cursor < end:
        if cursor + 4 > end:
            return None

        raw_type = int.from_bytes(
            data[cursor:cursor + 2],
            "big",
        )

        message_length = int.from_bytes(
            data[cursor + 2:cursor + 4],
            "big",
        )

        # The message length excludes its 4-byte message header.
        message_total_length = 4 + message_length

        # LDP messages contain at least a 4-byte Message ID.
        if message_length < 4:
            return None

        message_end = cursor + message_total_length

        if message_end > end:
            return None

        message_id = int.from_bytes(
            data[cursor + 4:cursor + 8],
            "big",
        )

        message_type = raw_type & 0x7FFF
        unknown_message_bit = bool(raw_type & 0x8000)

        messages.append(
            {
                "type": message_type,
                "name": MESSAGE_TYPES.get(
                    message_type,
                    f"Unknown (0x{message_type:04x})",
                ),
                "message_id": message_id,
                "message_length": message_length,
                "unknown_bit": unknown_message_bit,
                "body": data[cursor + 8:message_end],
            }
        )

        cursor = message_end

    if cursor != end:
        return None

    return {
        "offset": offset,
        "total_length": total_length,
        "pdu_length": pdu_length,
        "ldp_identifier": ".".join(
            str(byte) for byte in ldp_identifier
        ),
        "label_space": label_space,
        "messages": messages,
    }


def extract_ldp_pdus(stream_data):
    """
    Find complete LDP PDUs in a contiguous TCP data chunk.

    Byte-by-byte scanning allows recovery when the capture starts
    in the middle of an LDP PDU.
    """

    pdus = []
    offset = 0

    while offset + 10 <= len(stream_data):
        pdu = parse_ldp_pdu(stream_data, offset)

        if pdu is None:
            offset += 1
            continue

        pdus.append(pdu)
        offset += pdu["total_length"]

    return pdus


def main():
    if not PCAP_PATH.is_file():
        raise FileNotFoundError(
            f"PCAP file not found: {PCAP_PATH}"
        )

    packets = rdpcap(str(PCAP_PATH))
    streams = collect_tcp_streams(packets)

    message_counts = Counter()
    flow_counts = Counter()
    samples = []

    total_chunks = 0
    total_pdus = 0

    for flow, segments in streams.items():
        chunks = reassemble_tcp_segments(segments)
        flow_name = f"{flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}"

        for chunk in chunks:
            total_chunks += 1

            for pdu in extract_ldp_pdus(chunk):
                total_pdus += 1

                for message in pdu["messages"]:
                    name = message["name"]

                    message_counts[name] += 1
                    flow_counts[flow_name] += 1

                    if len(samples) < MAX_SAMPLES:
                        samples.append(
                            {
                                "flow": flow_name,
                                "pdu_length": pdu["pdu_length"],
                                "ldp_identifier": pdu["ldp_identifier"],
                                "label_space": pdu["label_space"],
                                "message": message,
                            }
                        )

    print("\n=== TCP Stream Analysis ===")
    print(f"TCP flows involving port {LDP_PORT}: {len(streams)}")
    print(f"Contiguous data chunks: {total_chunks}")
    print(f"Complete LDP PDUs parsed: {total_pdus}")

    print("\n=== LDP Message Counts ===")

    if not message_counts:
        print("No complete LDP messages were parsed.")
    else:
        for name, count in sorted(message_counts.items()):
            print(f"{name}: {count}")

    print("\n=== Message Samples ===")

    for sample in samples:
        message = sample["message"]

        print(
            f"\nFlow: {sample['flow']}\n"
            f"LDP Identifier: {sample['ldp_identifier']}\n"
            f"Label Space: {sample['label_space']}\n"
            f"PDU Length: {sample['pdu_length']}\n"
            f"Message Type: {message['name']}\n"
            f"Message ID: {message['message_id']}\n"
            f"Message Length: {message['message_length']}\n"
            f"Message Body Length: {len(message['body'])} bytes"
        )

    print("\n=== VPLS / MTU Investigation ===")
    print(
        "Label Mapping messages:",
        message_counts.get("Label Mapping", 0),
    )
    print(
        "This result does not establish the configured VPLS MTU."
    )


if __name__ == "__main__":
    main()