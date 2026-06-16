import json
from typing import Dict, List, Tuple
from datetime import datetime

from ..utils import AnalysisResult, ProtocolStats, Quadruple, TCPStream, HTTPMessage


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
    }
    return json.dumps(data, indent=indent, ensure_ascii=False)


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


def print_summary(result: AnalysisResult) -> str:
    output_parts = []

    output_parts.append(print_protocol_stats(result.protocol_stats))
    output_parts.append(print_top_ips(result.top_ips))
    output_parts.append(print_top_ports(result.top_ports))
    output_parts.append(print_timeline(result.timeline))
    output_parts.append(print_tcp_streams(result.tcp_streams))
    output_parts.append(print_http_messages(result.http_messages))

    return "\n".join(output_parts)


def write_json_file(result: AnalysisResult, output_path: str):
    json_str = to_json(result)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json_str)


def write_text_file(result: AnalysisResult, output_path: str):
    text_str = print_summary(result)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text_str)
