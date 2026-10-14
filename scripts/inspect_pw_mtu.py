from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from inspect_ldp_messages import (
    PCAP_PATH,
    collect_tcp_streams,
    extract_ldp_pdus,
    reassemble_tcp_segments,
)
from scapy.all import rdpcap


FEC_TYPES = {
    0x01: "Wildcard FEC",
    0x02: "Host Address FEC",
    0x03: "CR-LSP FEC",
    0x80: "PWid FEC",
    0x81: "Generalized PWid FEC",
}


def parse_tlvs(data: bytes) -> list[dict]:
    tlvs = []
    offset = 0

    while offset + 4 <= len(data):
        tlv_type = int.from_bytes(data[offset:offset + 2], "big")
        tlv_length = int.from_bytes(data[offset + 2:offset + 4], "big")

        value_start = offset + 4
        value_end = value_start + tlv_length

        if value_end > len(data):
            break

        tlvs.append({
            "type": tlv_type,
            "length": tlv_length,
            "value": data[value_start:value_end],
        })

        offset = value_end

    return tlvs


def main() -> None:
    if not PCAP_PATH.is_file():
        raise FileNotFoundError(f"PCAP not found: {PCAP_PATH}")

    packets = rdpcap(str(PCAP_PATH))
    streams = collect_tcp_streams(packets)

    count = 0

    for flow, segments in streams.items():
        for chunk in reassemble_tcp_segments(segments):
            for pdu in extract_ldp_pdus(chunk):
                for message in pdu["messages"]:
                    if message["name"] != "Label Mapping":
                        continue

                    count += 1

                    fec_tlvs = [
                        tlv for tlv in parse_tlvs(message["body"])
                        if tlv["type"] == 0x0100
                    ]

                    print(f"\nLabel Mapping #{count}")
                    print(f"Message ID: {message['message_id']}")

                    if not fec_tlvs:
                        print("FEC TLV: not found")
                        continue

                    for fec_tlv in fec_tlvs:
                        value = fec_tlv["value"]

                        if not value:
                            print("FEC value is empty")
                            continue

                        fec_type = value[0]

                        print(f"FEC Element Type: 0x{fec_type:02x}")
                        print(
                            "FEC Type:",
                            FEC_TYPES.get(fec_type, "Unknown/Other")
                        )
                        print(f"FEC Value: {value.hex(' ')}")

                        if fec_type == 0x80:
                            print(
                                "PWid FEC detected; "
                                "inspect its fields and interface parameters."
                            )

    print(f"\nTotal Label Mapping messages: {count}")


if __name__ == "__main__":
    main()