import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime

from ..utils import AnalysisResult, ProtocolStats, Quadruple, TCPStream, HTTPMessage, DNSStats
from ..extractors import dns_type_to_str, dns_rcode_to_str


def _format_timestamp(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except (ValueError, OSError, OverflowError):
        return f"{ts:.6f}"


def _protocol_to_string(protocol: str) -> str:
    mapping = {
        "IPV4": "IPv4",
        "IPV6": "IPv6",
        "TCP": "TCP",
        "UDP": "UDP",
        "ICMP": "ICMP",
        "OTHER": "Other",
    }
    return mapping.get(protocol, protocol)


def to_json(result: AnalysisResult, indent: int = 2) -> str:
    data = {
        "protocol_stats": {
            "total_packets": result.protocol_stats.total_packets,
            "total_bytes": result.protocol_stats.total_bytes,
            "ethernet_packets": result.protocol_stats.ethernet_packets,
            "ipv4_packets": result.protocol_stats.ipv4_packets,
            "ipv6_packets": result.protocol_stats.ipv6_packets,
            "tcp_packets": result.protocol_stats.tcp_packets,
            "udp_packets": result.protocol_stats.udp_packets,
            "icmp_packets": result.protocol_stats.icmp_packets,
            "http_requests": result.protocol_stats.http_requests,
            "http_responses": result.protocol_stats.http_responses,
            "ip_fragments": result.protocol_stats.ip_fragments,
            "reassembled_ip": result.protocol_stats.reassembled_ip,
        },
        "top_ips": [{"ip": ip, "count": count} for ip, count in result.top_ips],
        "top_ports": [{"port": port, "count": count} for port, count in result.top_ports],
        "timeline": [
            {
                "timestamp": ts,
                "time_str": _format_timestamp(ts),
                "protocol": _protocol_to_string(proto),
                "bytes": bytes_count,
            }
            for ts, proto, bytes_count in result.timeline[:1000]
        ],
        "tcp_streams": [
            {
                "client_ip": stream.client_quadruple.src_ip if stream.client_quadruple else q.src_ip,
                "client_port": stream.client_quadruple.src_port if stream.client_quadruple else q.src_port,
                "server_ip": stream.client_quadruple.dst_ip if stream.client_quadruple else q.dst_ip,
                "server_port": stream.client_quadruple.dst_port if stream.client_quadruple else q.dst_port,
                "client_bytes": len(stream.client_to_server),
                "server_bytes": len(stream.server_to_client),
                "is_closed": stream.is_closed,
            }
            for q, stream in result.tcp_streams.items()
        ],
        "http_messages": [
            {
                "type": "request" if msg.is_request else "response",
                "method": msg.method,
                "path": msg.path,
                "version": msg.version,
                "status_code": msg.status_code,
                "status_phrase": msg.status_phrase,
                "headers": msg.headers,
                "body_length": len(msg.body),
            }
            for msg in result.http_messages
        ],
        "dns_stats": _dns_stats_to_dict(result.dns_stats),
    }
    return json.dumps(data, indent=indent, ensure_ascii=False)


def _dns_stats_to_dict(dns_stats: Optional[DNSStats]) -> Optional[dict]:
    if dns_stats is None:
        return None

    query_types_list = []
    for qtype, count in sorted(dns_stats.query_types.items(), key=lambda x: -x[1]):
        query_types_list.append({
            "type": qtype,
            "type_str": dns_type_to_str(qtype),
            "count": count,
        })

    response_codes_list = []
    for rcode, count in sorted(dns_stats.response_codes.items(), key=lambda x: -x[1]):
        response_codes_list.append({
            "code": rcode,
            "code_str": dns_rcode_to_str(rcode),
            "count": count,
        })

    top_domains_list = []
    for domain, count in dns_stats.top_domains:
        top_domains_list.append({
            "domain": domain,
            "count": count,
        })

    return {
        "total_queries": dns_stats.total_queries,
        "total_responses": dns_stats.total_responses,
        "query_types": query_types_list,
        "response_codes": response_codes_list,
        "top_domains": top_domains_list,
        "rtt": {
            "min_ms": dns_stats.rtt_min * 1000,
            "max_ms": dns_stats.rtt_max * 1000,
            "avg_ms": dns_stats.rtt_avg * 1000,
            "samples": len(dns_stats.rtt_samples),
        },
        "unanswered_queries": dns_stats.unanswered_queries,
        "dns_packets": dns_stats.dns_packets,
    }


def _make_table(headers: List[str], rows: List[List[str]]) -> str:
    if not rows:
        return ""

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    separator = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    header_line = "|" + "|".join(f" {h:<{col_widths[i]}} " for i, h in enumerate(headers)) + "|"

    lines = [separator, header_line, separator]

    for row in rows:
        row_line = "|" + "|".join(f" {str(cell):<{col_widths[i]}} " for i, cell in enumerate(row)) + "|"
        lines.append(row_line)

    lines.append(separator)
    return "\n".join(lines)


def _format_bytes(num: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if num < 1024.0:
            return f"{num:.1f} {unit}" if unit != "B" else f"{num} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"


def print_protocol_stats(stats: ProtocolStats) -> str:
    headers = ["Protocol", "Packets", "Bytes", "Percentage"]
    total_pkts = stats.total_packets if stats.total_packets > 0 else 1

    rows = [
        ["Ethernet", f"{stats.ethernet_packets:,}", "-", "-"],
        ["IPv4", f"{stats.ipv4_packets:,}", _format_bytes(stats.ipv4_packets * 20), f"{stats.ipv4_packets/total_pkts*100:.1f}%"],
        ["IPv6", f"{stats.ipv6_packets:,}", _format_bytes(stats.ipv6_packets * 40), f"{stats.ipv6_packets/total_pkts*100:.1f}%"],
        ["TCP", f"{stats.tcp_packets:,}", "-", f"{stats.tcp_packets/total_pkts*100:.1f}%"],
        ["UDP", f"{stats.udp_packets:,}", "-", f"{stats.udp_packets/total_pkts*100:.1f}%"],
        ["ICMP", f"{stats.icmp_packets:,}", "-", f"{stats.icmp_packets/total_pkts*100:.1f}%"],
    ]

    summary = f"""
=== Protocol Distribution Statistics ===
Total Packets: {stats.total_packets:,}
Total Bytes:   {_format_bytes(stats.total_bytes)}

"""
    return summary + _make_table(headers, rows)


def print_top_ips(top_ips: List[Tuple[str, int]]) -> str:
    headers = ["Rank", "IP Address", "Packet Count", "Percentage"]
    total = sum(c for _, c in top_ips) if top_ips else 1

    rows = []
    for i, (ip, count) in enumerate(top_ips, 1):
        rows.append([str(i), ip, f"{count:,}", f"{count/total*100:.1f}%"])

    return "\n=== Top 10 IP Addresses ===\n" + _make_table(headers, rows)


def print_top_ports(top_ports: List[Tuple[int, int]]) -> str:
    headers = ["Rank", "Port", "Packet Count", "Percentage"]
    total = sum(c for _, c in top_ports) if top_ports else 1

    rows = []
    for i, (port, count) in enumerate(top_ports, 1):
        rows.append([str(i), str(port), f"{count:,}", f"{count/total*100:.1f}%"])

    return "\n=== Top 10 Ports ===\n" + _make_table(headers, rows)


def print_timeline(timeline: List[Tuple[float, str, int]], max_items: int = 20) -> str:
    if not timeline:
        return "\n=== Traffic Timeline ===\n(No packets)"

    headers = ["#", "Time", "Protocol", "Bytes"]
    display_items = timeline[:max_items]

    rows = []
    for i, (ts, proto, bytes_count) in enumerate(display_items, 1):
        rows.append([str(i), _format_timestamp(ts), _protocol_to_string(proto), str(bytes_count)])

    output = f"\n=== Traffic Timeline (first {max_items} of {len(timeline)}) ===\n"
    return output + _make_table(headers, rows)


def print_tcp_streams(streams: Dict[Quadruple, TCPStream]) -> str:
    if not streams:
        return "\n=== TCP Streams ===\n(No TCP streams)"

    headers = ["#", "Client", "Server", "C->S Bytes", "S->C Bytes", "Status"]

    rows = []
    for i, (q, stream) in enumerate(streams.items(), 1):
        if stream.client_quadruple:
            client = f"{stream.client_quadruple.src_ip}:{stream.client_quadruple.src_port}"
            server = f"{stream.client_quadruple.dst_ip}:{stream.client_quadruple.dst_port}"
        else:
            client = f"{q.src_ip}:{q.src_port}"
            server = f"{q.dst_ip}:{q.dst_port}"
        status = "Closed" if stream.is_closed else "Open"
        rows.append([
            str(i),
            client,
            server,
            _format_bytes(len(stream.client_to_server)),
            _format_bytes(len(stream.server_to_client)),
            status,
        ])

    output = f"\n=== TCP Streams ({len(streams)} total) ===\n"
    return output + _make_table(headers, rows)


def print_http_messages(messages: List[HTTPMessage]) -> str:
    if not messages:
        return "\n=== HTTP Messages ===\n(No HTTP messages)"

    headers = ["#", "Type", "Method/Status", "Path/Reason", "Body Length"]

    rows = []
    for i, msg in enumerate(messages, 1):
        msg_type = "REQ" if msg.is_request else "RESP"
        if msg.is_request:
            method_path = msg.method or "-"
            detail = msg.path or "-"
        else:
            method_path = str(msg.status_code) if msg.status_code else "-"
            detail = msg.status_phrase or "-"
        rows.append([
            str(i),
            msg_type,
            method_path,
            detail,
            _format_bytes(len(msg.body)),
        ])

    output = f"\n=== HTTP Messages ({len(messages)} total) ===\n"
    return output + _make_table(headers, rows)


def print_dns_stats(dns_stats: Optional[DNSStats]) -> str:
    if dns_stats is None or (dns_stats.total_queries == 0 and dns_stats.total_responses == 0):
        return "\n=== DNS Statistics ===\n(No DNS traffic)"

    output = f"\n=== DNS Statistics ===\n"
    output += f"Total Queries:  {dns_stats.total_queries:,}\n"
    output += f"Total Responses: {dns_stats.total_responses:,}\n"
    output += f"Unanswered Queries: {dns_stats.unanswered_queries:,}\n"
    output += "\n"

    if dns_stats.top_domains:
        headers = ["Rank", "Domain", "Query Count", "Percentage"]
        total = sum(c for _, c in dns_stats.top_domains) if dns_stats.top_domains else 1
        rows = []
        for i, (domain, count) in enumerate(dns_stats.top_domains, 1):
            rows.append([str(i), domain, f"{count:,}", f"{count/total*100:.1f}%"])
        output += "--- Top 10 Queried Domains ---\n"
        output += _make_table(headers, rows)
        output += "\n\n"

    if dns_stats.query_types:
        headers = ["Query Type", "Count", "Percentage"]
        total = sum(dns_stats.query_types.values()) if dns_stats.query_types else 1
        rows = []
        for qtype, count in sorted(dns_stats.query_types.items(), key=lambda x: -x[1]):
            rows.append([dns_type_to_str(qtype), f"{count:,}", f"{count/total*100:.1f}%"])
        output += "--- Query Type Distribution ---\n"
        output += _make_table(headers, rows)
        output += "\n\n"

    if dns_stats.response_codes:
        headers = ["Response Code", "Count", "Percentage"]
        total = sum(dns_stats.response_codes.values()) if dns_stats.response_codes else 1
        rows = []
        for rcode, count in sorted(dns_stats.response_codes.items(), key=lambda x: -x[1]):
            rows.append([dns_rcode_to_str(rcode), f"{count:,}", f"{count/total*100:.1f}%"])
        output += "--- Response Code Distribution ---\n"
        output += _make_table(headers, rows)
        output += "\n\n"

    if dns_stats.rtt_samples:
        headers = ["Metric", "Value"]
        rows = [
            ["RTT Min", f"{dns_stats.rtt_min * 1000:.3f} ms"],
            ["RTT Max", f"{dns_stats.rtt_max * 1000:.3f} ms"],
            ["RTT Avg", f"{dns_stats.rtt_avg * 1000:.3f} ms"],
            ["Samples", f"{len(dns_stats.rtt_samples):,}"],
        ]
        output += "--- Query Response Time (RTT) ---\n"
        output += _make_table(headers, rows)

    return output


def print_dns_packets(dns_stats: Optional[DNSStats], max_items: int = 20) -> str:
    if dns_stats is None or not dns_stats.dns_packets:
        return "\n=== DNS Packets ===\n(No DNS packets)"

    headers = ["#", "Time", "Type", "Src", "Dst", "Transaction ID", "QName", "QType", "RCode"]

    display_packets = dns_stats.dns_packets[:max_items]
    rows = []
    for i, pkt in enumerate(display_packets, 1):
        pkt_type = "RESP" if pkt["is_response"] else "QUERY"
        qname = pkt["questions"][0]["qname"] if pkt["questions"] else "-"
        qtype = pkt["questions"][0]["qtype_str"] if pkt["questions"] else "-"
        rcode = pkt["rcode_str"] if pkt["is_response"] else "-"
        src = f"{pkt['src_ip']}:{pkt['src_port']}"
        dst = f"{pkt['dst_ip']}:{pkt['dst_port']}"
        rows.append([
            str(i),
            _format_timestamp(pkt["timestamp"]),
            pkt_type,
            src,
            dst,
            f"0x{pkt['transaction_id']:04x}",
            qname,
            qtype,
            rcode,
        ])

    output = f"\n=== DNS Packets (first {max_items} of {len(dns_stats.dns_packets)}) ===\n"
    return output + _make_table(headers, rows)


def print_summary(result: AnalysisResult) -> str:
    output_parts = []

    output_parts.append(print_protocol_stats(result.protocol_stats))
    output_parts.append(print_top_ips(result.top_ips))
    output_parts.append(print_top_ports(result.top_ports))
    output_parts.append(print_timeline(result.timeline))
    output_parts.append(print_tcp_streams(result.tcp_streams))
    output_parts.append(print_http_messages(result.http_messages))
    output_parts.append(print_dns_stats(result.dns_stats))

    return "\n".join(output_parts)


def write_json_file(result: AnalysisResult, output_path: str):
    json_str = to_json(result)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json_str)


def write_text_file(result: AnalysisResult, output_path: str):
    text_str = print_summary(result)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text_str)
