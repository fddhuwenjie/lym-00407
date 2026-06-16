#!/usr/bin/env python3
"""Generate a test PCAP file with DNS packets and verify DNS parsing."""
import struct
import os
import sys
import socket

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pcap_analyzer.main import analyze_pcap
from pcap_analyzer.analytics.output import to_json, print_summary, print_dns_packets
from pcap_analyzer.extractors.dns_extractor import parse_dns, dns_type_to_str, dns_rcode_to_str


PCAP_MAGIC = 0xA1B2C3D4


def _build_eth_header(src_mac: bytes, dst_mac: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", 0x0800)


def _build_ip_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int) -> bytes:
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    total_len = 20 + payload_len
    ip_hdr = struct.pack(">BBHHHBBH",
        0x45,
        0,
        total_len,
        0x1234,
        0,
        64,
        protocol,
        0,
    )
    ip_hdr += src_bytes + dst_bytes
    return ip_hdr


def _build_udp_header(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack(">HHHH", src_port, dst_port, length, 0)


def _encode_domain_name(domain: str) -> bytes:
    result = b""
    for label in domain.split("."):
        result += bytes([len(label)]) + label.encode("ascii")
    result += b"\x00"
    return result


def _build_dns_query(transaction_id: int, domain: str, qtype: int = 1) -> bytes:
    flags = 0x0100
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack(">HHHHHH",
        transaction_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
    )

    question = _encode_domain_name(domain)
    question += struct.pack(">HH", qtype, 1)

    return header + question


def _build_dns_response(
    transaction_id: int,
    domain: str,
    qtype: int,
    rcode: int = 0,
    answers: list = None,
) -> bytes:
    flags = 0x8180 | rcode
    qdcount = 1
    ancount = len(answers) if answers else 0
    nscount = 0
    arcount = 0

    header = struct.pack(">HHHHHH",
        transaction_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
    )

    question = _encode_domain_name(domain)
    question += struct.pack(">HH", qtype, 1)

    answer_section = b""
    if answers:
        for ans in answers:
            ans_name = b"\xc0\x0c"
            ans_type = struct.pack(">H", ans["type"])
            ans_class = struct.pack(">H", 1)
            ans_ttl = struct.pack(">I", ans.get("ttl", 300))
            rdata = ans["rdata"]
            ans_rdlength = struct.pack(">H", len(rdata))
            answer_section += ans_name + ans_type + ans_class + ans_ttl + ans_rdlength + rdata

    return header + question + answer_section


def _a_record_rdata(ip: str) -> bytes:
    return socket.inet_aton(ip)


def _aaaa_record_rdata(ipv6: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, ipv6)


def _cname_record_rdata(domain: str) -> bytes:
    return _encode_domain_name(domain)


def _write_pcap_packet(f, timestamp_sec: int, timestamp_usec: int, data: bytes):
    f.write(struct.pack("<IIII", timestamp_sec, timestamp_usec, len(data), len(data)))
    f.write(data)


def generate_test_pcap(output_path: str):
    """Generate a test PCAP with DNS queries and responses."""
    client_mac = b"\x00\x11\x22\x33\x44\x55"
    server_mac = b"\x00\xaa\xbb\xcc\xdd\xee"
    client_ip = "192.168.1.100"
    server_ip = "8.8.8.8"
    client_port = 12345

    with open(output_path, "wb") as f:
        f.write(struct.pack("<IHHIIII",
            PCAP_MAGIC,
            2,
            4,
            0,
            0,
            65535,
            1,
        ))

        ts_base = 1000000
        pkt_num = 0

        test_domains = [
            ("www.example.com", 1, "93.184.216.34", None),
            ("mail.example.com", 5, None, "mail.google.com"),
            ("ipv6.example.com", 28, None, None),
            ("www.google.com", 1, "142.250.80.46", None),
            ("api.github.com", 1, "140.82.112.6", None),
            ("nonexistent.example.com", 1, None, None),
            ("www.cnn.com", 1, "151.101.1.67", None),
            ("www.nytimes.com", 1, "151.101.1.164", None),
            ("cdn.cloudflare.com", 28, None, None),
            ("test.example.com", 1, "10.0.0.1", None),
            ("service.local", 1, "192.168.1.10", None),
            ("download.example.org", 5, None, "cdn.example.org"),
        ]

        for i, (domain, qtype, a_ip, cname_target) in enumerate(test_domains):
            txn_id = 0x1000 + i
            ts = ts_base + i * 10

            query_dns = _build_dns_query(txn_id, domain, qtype)
            udp_query = _build_udp_header(client_port + i, 53, query_dns)
            ip_query = _build_ip_header(client_ip, server_ip, 17, len(udp_query))
            eth_query = _build_eth_header(client_mac, server_mac)
            pkt_query = eth_query + ip_query + udp_query + query_dns

            _write_pcap_packet(f, ts, 10000 + i * 100, pkt_query)

            if domain == "nonexistent.example.com":
                answers = []
                rcode = 3
            else:
                answers = []
                rcode = 0
                if qtype == 1 and a_ip:
                    answers.append({"type": 1, "ttl": 300, "rdata": _a_record_rdata(a_ip)})
                elif qtype == 28:
                    answers.append({"type": 28, "ttl": 300, "rdata": _aaaa_record_rdata("2001:db8::1")})
                elif qtype == 5 and cname_target:
                    answers.append({"type": 5, "ttl": 300, "rdata": _cname_record_rdata(cname_target)})

            resp_dns = _build_dns_response(txn_id, domain, qtype, rcode, answers)
            udp_resp = _build_udp_header(53, client_port + i, resp_dns)
            ip_resp = _build_ip_header(server_ip, client_ip, 17, len(udp_resp))
            eth_resp = _build_eth_header(server_mac, client_mac)
            pkt_resp = eth_resp + ip_resp + udp_resp + resp_dns

            _write_pcap_packet(f, ts, 50000 + i * 100, pkt_resp)

    print(f"Generated test PCAP: {output_path}")


def test_dns_parsing():
    """Test the DNS parser directly."""
    print("\n" + "=" * 60)
    print("TEST: DNS Packet Parsing")
    print("=" * 60)

    domain = "www.example.com"
    query = _build_dns_query(0x1234, domain, 1)

    dns = parse_dns(query)
    assert dns is not None, "Failed to parse DNS query"
    assert dns.transaction_id == 0x1234, f"Wrong transaction ID: {dns.transaction_id}"
    assert dns.qr is False, "Should be a query"
    assert dns.rcode == 0, f"Wrong rcode: {dns.rcode}"
    assert dns.qdcount == 1, f"Wrong qdcount: {dns.qdcount}"
    assert len(dns.questions) == 1, "Wrong number of questions"
    assert dns.questions[0].qname == domain, f"Wrong qname: {dns.questions[0].qname}"
    assert dns.questions[0].qtype == 1, f"Wrong qtype: {dns.questions[0].qtype}"
    print("  ✓ DNS query parsing works")

    answers = [{"type": 1, "ttl": 300, "rdata": _a_record_rdata("93.184.216.34")}]
    response = _build_dns_response(0x1234, domain, 1, 0, answers)

    dns_resp = parse_dns(response)
    assert dns_resp is not None, "Failed to parse DNS response"
    assert dns_resp.qr is True, "Should be a response"
    assert dns_resp.rcode == 0, f"Wrong rcode: {dns_resp.rcode}"
    assert dns_resp.ancount == 1, f"Wrong ancount: {dns_resp.ancount}"
    assert len(dns_resp.answers) == 1, "Wrong number of answers"
    assert dns_resp.answers[0].rtype == 1, "Wrong answer type"
    assert dns_resp.answers[0].rdata == "93.184.216.34", f"Wrong A record data: {dns_resp.answers[0].rdata}"
    print("  ✓ DNS response with A record parsing works")

    cname_answers = [{"type": 5, "ttl": 300, "rdata": _cname_record_rdata("target.example.com")}]
    cname_resp = _build_dns_response(0x5678, "alias.example.com", 5, 0, cname_answers)
    dns_cname = parse_dns(cname_resp)
    assert dns_cname is not None, "Failed to parse CNAME response"
    assert dns_cname.answers[0].rtype == 5, "Wrong CNAME type"
    assert dns_cname.answers[0].rdata == "target.example.com", f"Wrong CNAME data: {dns_cname.answers[0].rdata}"
    print("  ✓ DNS CNAME record parsing works")

    aaaa_answers = [{"type": 28, "ttl": 300, "rdata": _aaaa_record_rdata("2001:db8::1")}]
    aaaa_resp = _build_dns_response(0x9abc, "ipv6.example.com", 28, 0, aaaa_answers)
    dns_aaaa = parse_dns(aaaa_resp)
    assert dns_aaaa is not None, "Failed to parse AAAA response"
    assert dns_aaaa.answers[0].rtype == 28, "Wrong AAAA type"
    assert dns_aaaa.answers[0].rdata == "2001:db8::1", f"Wrong AAAA data: {dns_aaaa.answers[0].rdata}"
    print("  ✓ DNS AAAA record parsing works")

    print("  ✓ All DNS parsing tests passed!")
    return True


def test_full_analysis():
    """Test full PCAP analysis with DNS."""
    print("\n" + "=" * 60)
    print("TEST: Full PCAP Analysis with DNS")
    print("=" * 60)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    test_file = os.path.join(base_dir, "test_dns.pcap")
    generate_test_pcap(test_file)

    result, packet_count, elapsed = analyze_pcap(test_file, verbose=False)

    print(f"  Total packets: {packet_count}")
    print(f"  DNS stats present: {result.dns_stats is not None}")

    assert result.dns_stats is not None, "DNS stats should not be None"
    dns = result.dns_stats
    print(f"  Total queries: {dns.total_queries}")
    print(f"  Total responses: {dns.total_responses}")
    print(f"  Unanswered: {dns.unanswered_queries}")

    assert dns.total_queries == 12, f"Expected 12 queries, got {dns.total_queries}"
    assert dns.total_responses == 12, f"Expected 12 responses, got {dns.total_responses}"
    print("  ✓ Query/response counts correct")

    assert len(dns.top_domains) > 0, "Should have top domains"
    print(f"  Top domain: {dns.top_domains[0][0]} ({dns.top_domains[0][1]} queries)")
    print("  ✓ Top domains computed")

    assert len(dns.rtt_samples) > 0, "Should have RTT samples"
    print(f"  RTT samples: {len(dns.rtt_samples)}")
    print(f"  RTT min: {dns.rtt_min * 1000:.3f} ms")
    print(f"  RTT max: {dns.rtt_max * 1000:.3f} ms")
    print(f"  RTT avg: {dns.rtt_avg * 1000:.3f} ms")
    print("  ✓ RTT computation works")

    assert 3 in dns.response_codes, "Should have NXDOMAIN responses"
    print(f"  NXDOMAIN count: {dns.response_codes[3]}")
    print("  ✓ Response code distribution works")

    json_str = to_json(result)
    assert "dns_stats" in json_str, "JSON should have dns_stats"
    print(f"  ✓ JSON output valid ({len(json_str)} bytes)")

    text_str = print_summary(result)
    assert "DNS Statistics" in text_str, "Text output should have DNS section"
    assert "Top 10 Queried Domains" in text_str, "Should have top domains table"
    assert "Response Code Distribution" in text_str, "Should have response code table"
    assert "Query Response Time" in text_str, "Should have RTT section"
    print("  ✓ Text output with ASCII tables works")

    print("  ✓ Full analysis test passed!")
    return True


def main():
    all_passed = True

    try:
        if not test_dns_parsing():
            all_passed = False
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  ✗ DNS parsing test failed: {e}")
        all_passed = False

    try:
        if not test_full_analysis():
            all_passed = False
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  ✗ Full analysis test failed: {e}")
        all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("✓ ALL DNS TESTS PASSED")
        return 0
    else:
        print("✗ SOME DNS TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
