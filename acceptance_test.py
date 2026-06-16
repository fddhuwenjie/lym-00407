#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pcap_analyzer.main import analyze_pcap
from pcap_analyzer.analytics.output import to_json, print_summary
from pcap_analyzer.core import PcapParser, parse_packet, IPReassembler
from pcap_analyzer.utils.constants import LINKTYPE_ETHERNET


def _get_test_files():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return {
        "capture": os.path.join(base_dir, "test_capture.pcap"),
        "fragmented": os.path.join(base_dir, "test_fragmented.pcap"),
    }


def _run_tshark(file_path, extra_args=None):
    cmd = [
        "tshark",
        "-r", file_path,
        "-o", "tcp.relative_sequence_numbers:FALSE",
        "-T", "json",
        "-e", "frame.number",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "ip.id",
        "-e", "ip.ttl",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.seq",
        "-e", "tcp.ack",
        "-e", "tcp.flags",
        "-e", "tcp.len",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "udp.length",
        "-e", "icmp.type",
        "-e", "icmp.code",
    ]
    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  tshark error: {result.stderr.strip()}")
        return []

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []


def _get_layer_field(layers, field_name):
    values = layers.get(field_name)
    if values and len(values) > 0:
        return values[0]
    return None


def _compare(tshark_val, our_val, label):
    if tshark_val is None:
        return True
    if str(tshark_val) != str(our_val):
        print(f"    ✗ {label}: tshark={tshark_val}, ours={our_val}")
        return False
    return True


def test_tshark_field_consistency():
    print("\n" + "=" * 60)
    print("TEST 1: tshark Field Consistency")
    print("=" * 60)

    test_files = _get_test_files()
    file_path = test_files["capture"]
    if not os.path.exists(file_path):
        print(f"  ✗ Test file not found: {file_path}")
        return False

    tshark_packets = _run_tshark(file_path)
    if not tshark_packets:
        print("  ✗ Failed to get tshark output")
        return False

    our_packets = []
    with PcapParser(file_path, use_mmap=True) as parser:
        link_type = parser.file_info.link_type if parser.file_info else LINKTYPE_ETHERNET
        for raw_pkt in parser:
            packet = parse_packet(
                timestamp=raw_pkt.timestamp,
                captured_len=raw_pkt.captured_len,
                original_len=raw_pkt.original_len,
                link_type=link_type,
                data=raw_pkt.data,
            )
            our_packets.append(packet)

    if len(tshark_packets) != len(our_packets):
        print(f"  ✗ Packet count mismatch: tshark={len(tshark_packets)}, ours={len(our_packets)}")
        return False

    print(f"  Comparing {len(tshark_packets)} packets...")

    all_passed = True
    mismatches = 0
    for i, (t_pkt, o_pkt) in enumerate(zip(tshark_packets, our_packets), 1):
        layers = t_pkt.get("_source", {}).get("layers", {})
        pkt_ok = True

        ip_src = _get_layer_field(layers, "ip.src")
        ip_dst = _get_layer_field(layers, "ip.dst")
        ip_proto = _get_layer_field(layers, "ip.proto")
        ip_ttl = _get_layer_field(layers, "ip.ttl")

        if ip_src:
            if not _compare(ip_src, o_pkt.ipv4.src_ip if o_pkt.ipv4 else None, f"Pkt{i} ip.src"):
                pkt_ok = False
            if not _compare(ip_dst, o_pkt.ipv4.dst_ip if o_pkt.ipv4 else None, f"Pkt{i} ip.dst"):
                pkt_ok = False
            if not _compare(ip_proto, o_pkt.ipv4.protocol if o_pkt.ipv4 else None, f"Pkt{i} ip.proto"):
                pkt_ok = False
            if not _compare(ip_ttl, o_pkt.ipv4.ttl if o_pkt.ipv4 else None, f"Pkt{i} ip.ttl"):
                pkt_ok = False

        if ip_proto == "6" and o_pkt.tcp:
            tcp_srcport = _get_layer_field(layers, "tcp.srcport")
            tcp_dstport = _get_layer_field(layers, "tcp.dstport")
            tcp_seq = _get_layer_field(layers, "tcp.seq")
            tcp_ack = _get_layer_field(layers, "tcp.ack")

            if not _compare(tcp_srcport, o_pkt.tcp.src_port, f"Pkt{i} tcp.srcport"):
                pkt_ok = False
            if not _compare(tcp_dstport, o_pkt.tcp.dst_port, f"Pkt{i} tcp.dstport"):
                pkt_ok = False
            if not _compare(tcp_seq, o_pkt.tcp.seq_num, f"Pkt{i} tcp.seq"):
                pkt_ok = False
            if tcp_ack is not None:
                if not _compare(tcp_ack, o_pkt.tcp.ack_num, f"Pkt{i} tcp.ack"):
                    pkt_ok = False

        elif ip_proto == "17" and o_pkt.udp:
            udp_srcport = _get_layer_field(layers, "udp.srcport")
            udp_dstport = _get_layer_field(layers, "udp.dstport")
            if not _compare(udp_srcport, o_pkt.udp.src_port, f"Pkt{i} udp.srcport"):
                pkt_ok = False
            if not _compare(udp_dstport, o_pkt.udp.dst_port, f"Pkt{i} udp.dstport"):
                pkt_ok = False

        elif ip_proto == "1" and o_pkt.icmp:
            icmp_type = _get_layer_field(layers, "icmp.type")
            icmp_code = _get_layer_field(layers, "icmp.code")
            if not _compare(icmp_type, o_pkt.icmp.type, f"Pkt{i} icmp.type"):
                pkt_ok = False
            if not _compare(icmp_code, o_pkt.icmp.code, f"Pkt{i} icmp.code"):
                pkt_ok = False

        if not pkt_ok:
            all_passed = False
            mismatches += 1

    if all_passed:
        print(f"  ✓ All {len(tshark_packets)} packets match tshark output")
    else:
        print(f"  ✗ {mismatches}/{len(tshark_packets)} packets have field mismatches")

    return all_passed


def test_tcp_reassembly_http():
    print("\n" + "=" * 60)
    print("TEST 2: TCP Reassembly & HTTP Extraction")
    print("=" * 60)

    test_files = _get_test_files()
    file_path = test_files["capture"]
    if not os.path.exists(file_path):
        print(f"  ✗ Test file not found: {file_path}")
        return False

    result, _, _ = analyze_pcap(file_path, verbose=False)

    http_msgs = result.http_messages
    print(f"  Found {len(http_msgs)} HTTP messages")

    request = None
    response = None
    for msg in http_msgs:
        if msg.is_request and request is None:
            request = msg
        elif not msg.is_request and response is None:
            response = msg

    ok = True

    if request is None:
        print("  ✗ No HTTP request found")
        ok = False
    else:
        if request.method != "GET":
            print(f"  ✗ Request method: expected GET, got {request.method}")
            ok = False
        else:
            print(f"  ✓ Request method: {request.method}")

        if request.path != "/index.html":
            print(f"  ✗ Request path: expected /index.html, got {request.path}")
            ok = False
        else:
            print(f"  ✓ Request path: {request.path}")

        if request.version != "HTTP/1.1":
            print(f"  ✗ Request version: expected HTTP/1.1, got {request.version}")
            ok = False
        else:
            print(f"  ✓ Request version: {request.version}")

        if "Host" not in request.headers:
            print("  ✗ Request missing Host header")
            ok = False
        else:
            print(f"  ✓ Request Host header: {request.headers['Host']}")

    if response is None:
        print("  ✗ No HTTP response found")
        ok = False
    else:
        if response.status_code != 200:
            print(f"  ✗ Response status: expected 200, got {response.status_code}")
            ok = False
        else:
            print(f"  ✓ Response status code: {response.status_code}")

        if response.status_phrase != "OK":
            print(f"  ✗ Response phrase: expected OK, got {response.status_phrase}")
            ok = False
        else:
            print(f"  ✓ Response status phrase: {response.status_phrase}")

        if response.body != b"Hello, World!":
            print(f"  ✗ Response body: expected b'Hello, World!', got {repr(response.body)}")
            ok = False
        else:
            print(f"  ✓ Response body: {repr(response.body)}")

    if ok:
        print("  ✓ TCP reassembly & HTTP extraction passed")
    return ok


def test_ip_reassembly():
    print("\n" + "=" * 60)
    print("TEST 3: IP Fragment Reassembly")
    print("=" * 60)

    from pcap_analyzer.utils import IPv4Packet, ReassembledIPPacket

    reassembler = IPReassembler(timeout=30.0)

    payload_a = b"A" * 100
    payload_b = b"B" * 100
    payload_c = b"C" * 56
    total_payload = payload_a + payload_b + payload_c

    frag1 = IPv4Packet(
        version=4, ihl=20, tos=0, total_length=120, identification=0xabcd,
        flags=0x01, fragment_offset=0, ttl=64, protocol=6, checksum=0,
        src_ip="192.168.1.10", dst_ip="10.0.0.10", options=b"",
        payload=payload_a, is_fragmented=True, more_fragments=True,
    )
    frag2 = IPv4Packet(
        version=4, ihl=20, tos=0, total_length=120, identification=0xabcd,
        flags=0x01, fragment_offset=100, ttl=64, protocol=6, checksum=0,
        src_ip="192.168.1.10", dst_ip="10.0.0.10", options=b"",
        payload=payload_b, is_fragmented=True, more_fragments=True,
    )
    frag3 = IPv4Packet(
        version=4, ihl=20, tos=0, total_length=76, identification=0xabcd,
        flags=0x00, fragment_offset=200, ttl=64, protocol=6, checksum=0,
        src_ip="192.168.1.10", dst_ip="10.0.0.10", options=b"",
        payload=payload_c, is_fragmented=True, more_fragments=False,
    )

    reassembler.add_fragment(frag1)
    reassembler.add_fragment(frag2)
    result = reassembler.add_fragment(frag3)

    ok = True
    if result is None:
        print("  ✗ Reassembly returned None")
        ok = False
    else:
        if result.total_fragments != 3:
            print(f"  ✗ Fragment count: expected 3, got {result.total_fragments}")
            ok = False
        else:
            print(f"  ✓ Fragment count: {result.total_fragments}")

        if result.payload != total_payload:
            print(f"  ✗ Payload mismatch")
            ok = False
        else:
            print(f"  ✓ Reassembled payload matches ({len(total_payload)} bytes)")

    reassembler2 = IPReassembler(timeout=30.0)
    reassembler2.add_fragment(frag3)
    reassembler2.add_fragment(frag1)
    result2 = reassembler2.add_fragment(frag2)

    if result2 is None:
        print("  ✗ Out-of-order reassembly returned None")
        ok = False
    elif result2.payload != total_payload:
        print("  ✗ Out-of-order payload mismatch")
        ok = False
    else:
        print("  ✓ Out-of-order reassembly passed")

    if ok:
        print("  ✓ IP fragment reassembly passed")
    return ok


def test_output_format():
    print("\n" + "=" * 60)
    print("TEST 4: Output Format (JSON + ASCII Table)")
    print("=" * 60)

    test_files = _get_test_files()
    file_path = test_files["capture"]
    if not os.path.exists(file_path):
        print(f"  ✗ Test file not found: {file_path}")
        return False

    result, _, _ = analyze_pcap(file_path, verbose=False)

    ok = True

    json_str = to_json(result)
    try:
        json_data = json.loads(json_str)
        print(f"  ✓ JSON output valid ({len(json_str)} bytes)")

        required_keys = [
            "protocol_stats", "top_ips", "top_ports",
            "timeline", "tcp_streams", "http_messages",
        ]
        for key in required_keys:
            if key not in json_data:
                print(f"  ✗ JSON missing key: {key}")
                ok = False
            else:
                print(f"  ✓ JSON key present: {key}")
    except json.JSONDecodeError as e:
        print(f"  ✗ JSON parse error: {e}")
        ok = False

    text_str = print_summary(result)
    if not text_str:
        print("  ✗ Text output is empty")
        ok = False
    else:
        print(f"  ✓ Text output generated ({len(text_str)} bytes)")

        table_markers = ["+", "|", "-"]
        has_table = all(m in text_str for m in table_markers)
        if not has_table:
            print("  ✗ Text output missing ASCII table markers")
            ok = False
        else:
            print("  ✓ ASCII table format detected")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json_path = f.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        text_path = f.name

    try:
        from pcap_analyzer.analytics.output import write_json_file, write_text_file
        write_json_file(result, json_path)
        write_text_file(result, text_path)

        if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
            print(f"  ✓ JSON file written ({os.path.getsize(json_path)} bytes)")
        else:
            print("  ✗ JSON file write failed")
            ok = False

        if os.path.exists(text_path) and os.path.getsize(text_path) > 0:
            print(f"  ✓ Text file written ({os.path.getsize(text_path)} bytes)")
        else:
            print("  ✗ Text file write failed")
            ok = False
    finally:
        for p in (json_path, text_path):
            if os.path.exists(p):
                os.unlink(p)

    if ok:
        print("  ✓ Output format validation passed")
    return ok


def test_performance():
    print("\n" + "=" * 60)
    print("TEST 5: Performance (< 5s for 10MB)")
    print("=" * 60)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    large_file = os.path.join(base_dir, "large_test.pcap")

    if not os.path.exists(large_file):
        print(f"  Large test file not found: {large_file}")
        print("  Generating 10MB test pcap...")
        _generate_large_pcap(large_file, target_size_mb=10)

    file_size = os.path.getsize(large_file)
    file_mb = file_size / (1024 * 1024)
    print(f"  Test file: {file_mb:.2f} MB")

    start = time.time()
    result, packet_count, elapsed = analyze_pcap(large_file, verbose=False)
    duration = time.time() - start

    throughput = file_mb / duration if duration > 0 else 0

    print(f"  Parsed {packet_count:,} packets in {duration:.3f}s")
    print(f"  Throughput: {throughput:.2f} MB/s")

    if duration < 5.0:
        print(f"  ✓ Performance test passed ({duration:.3f}s < 5s)")
        return True
    else:
        print(f"  ✗ Performance test failed ({duration:.3f}s >= 5s)")
        return False


def _generate_large_pcap(output_path, target_size_mb=10):
    import random
    PCAP_MAGIC = 0xA1B2C3D4
    target_size = target_size_mb * 1024 * 1024

    with open(output_path, "wb") as f:
        f.write(struct_pack("<I", PCAP_MAGIC))
        f.write(struct_pack("<H", 2))
        f.write(struct_pack("<H", 4))
        f.write(struct_pack("<I", 0))
        f.write(struct_pack("<I", 0))
        f.write(struct_pack("<I", 65535))
        f.write(struct_pack("<I", 1))

        ts = 1000000000
        count = 0
        while f.tell() < target_size:
            eth_dst = os.urandom(6)
            eth_src = os.urandom(6)
            eth_type = struct_pack(">H", 0x0800)

            payload_len = random.randint(0, 1400)
            ip_total = 40 + payload_len
            ip_id = random.randint(0, 65535)
            ip_proto = random.choice([6, 17, 1])

            ip_hdr = struct_pack(">BBHHHBBH", 0x45, 0, ip_total, ip_id, 0, 64, ip_proto, 0)
            ip_hdr += bytes([192, 168, random.randint(0, 255), random.randint(1, 254)])
            ip_hdr += bytes([10, 0, random.randint(0, 255), random.randint(1, 254)])

            if ip_proto == 6:
                tcp_hdr = struct_pack(">HHIIHHHH",
                    random.randint(1024, 65535), random.choice([80, 443, 22]),
                    random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF),
                    (5 << 12) | 0x10, 65535, 0, 0)
                pkt = eth_dst + eth_src + eth_type + ip_hdr + tcp_hdr + os.urandom(payload_len)
            elif ip_proto == 17:
                udp_hdr = struct_pack(">HHHH",
                    random.randint(1024, 65535), random.choice([53, 123]),
                    8 + payload_len, 0)
                pkt = eth_dst + eth_src + eth_type + ip_hdr + udp_hdr + os.urandom(payload_len)
            else:
                icmp_hdr = struct_pack(">BBHHH", 8, 0, 0, 1, 1)
                pkt = eth_dst + eth_src + eth_type + ip_hdr + icmp_hdr + os.urandom(max(0, payload_len - 8))

            f.write(struct_pack("<IIII", ts, random.randint(0, 999999), len(pkt), len(pkt)))
            f.write(pkt)
            ts += 1
            count += 1


def struct_pack(fmt, *args):
    import struct as _struct
    return _struct.pack(fmt, *args)


def main():
    print("=" * 60)
    print("PCAP Analyzer Acceptance Tests")
    print("=" * 60)

    results = {}

    results["tshark_consistency"] = test_tshark_field_consistency()
    results["tcp_http"] = test_tcp_reassembly_http()
    results["ip_reassembly"] = test_ip_reassembly()
    results["output_format"] = test_output_format()
    results["performance"] = test_performance()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    all_passed = True
    for name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}")
        if not passed:
            all_passed = False

    print()
    if all_passed:
        print("✓ ALL ACCEPTANCE TESTS PASSED")
        return 0
    else:
        print("✗ SOME ACCEPTANCE TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
