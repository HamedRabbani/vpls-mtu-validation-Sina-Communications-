from pathlib import Path
from scripts.inspect_bgp_mtu import (
    extract_tcp_streams,
    reassemble_stream,
    extract_bgp_messages,
    parse_bgp_update,
    MP_REACH_NLRI_ATTRIBUTE,
)

pcap = Path("data/VPLS_PE(cisco)_PE(cisco).pcapng")
capture = extract_tcp_streams(pcap)

for (src, dst), segments in capture["streams"].items():
    stream = reassemble_stream(segments)

    for packet_no, message in enumerate(extract_bgp_messages(stream), 1):
        update = parse_bgp_update(message)
        if not update:
            continue

        for attr in update["path_attributes"]:
            if attr["type"] != MP_REACH_NLRI_ATTRIBUTE:
                continue

            decoded = attr.get("decoded", {})
            if decoded.get("afi") != 25 or decoded.get("safi") != 65:
                continue

            print(f"\nStream: {src} -> {dst}")
            print(f"UPDATE #{packet_no}")
            print(f"MP_REACH raw: {attr['raw']}")
            print(f"Next hop: {decoded.get('next_hop')}")
            print(f"Reserved: {decoded.get('reserved')}")
            print(f"NLRI raw: {decoded.get('raw_nlri')}")
            print(f"NLRI decoded: {decoded.get('nlri')}")
            print(f"Parse errors: {decoded.get('parse_errors', [])}")
