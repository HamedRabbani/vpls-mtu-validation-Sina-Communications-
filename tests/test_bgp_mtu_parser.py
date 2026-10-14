
from scripts.inspect_bgp_mtu import (
    decode_extended_communities,
    decode_rd,
    decode_vpls_nlri,
    parse_mp_reach_nlri,
)


def test_decode_route_distinguisher():
    raw = bytes.fromhex("0000004000000004")

    assert decode_rd(raw) == "64:4"


def test_decode_vpls_nlri():
    raw = bytes.fromhex(
        "88"
        "0000004000000004"
        "0003"
        "0001"
        "000a"
        "000101"
    )

    result = decode_vpls_nlri(raw)

    assert result["route_distinguisher"] == "64:4"
    assert result["ve_id"] == 3
    assert result["ve_block_offset"] == 1
    assert result["ve_block_size"] == 10
    assert result["label_base"] == 16


def test_decode_extended_communities():
    raw = bytes.fromhex(
        "0002004000000004"
        "800a130005dc0000"
    )

    result = decode_extended_communities(raw)

    assert "64:4" in result["route_targets"]
    assert result["layer2_mtu"][0]["mtu"] == 1500


def test_parse_mp_reach_nlri():
    raw = bytes.fromhex(
        "0019"
        "41"
        "04"
        "40401100"
        "00"
        "88"
        "0000004000000004"
        "0003"
        "0001"
        "000a"
        "000101"
    )
    result = parse_mp_reach_nlri(raw)

    assert result["afi"] == 25
    assert result["safi"] == 65
    assert result["next_hop"] == "64.64.17.0"
    assert result["nlri"][0]["route_distinguisher"] == "64:4"
    assert result["nlri"][0]["ve_id"] == 3

