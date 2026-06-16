from typing import List, Dict, Tuple, Optional
from collections import defaultdict, Counter

from ..utils import (
    Packet,
    ProtocolStats,
    AnalysisResult,
    Quadruple,
    TCPStream,
    HTTPMessage,
    DNSStats,
    DNSPacket,
)
from ..extractors import HTTPExtractor, parse_dns, dns_type_to_str, dns_rcode_to_str, dns_opcode_to_str


class Analyzer:
    def __init__(self):
        self._stats = ProtocolStats()
        self._ip_counter: Counter = Counter()
        self._port_counter: Counter = Counter()
        self._timeline: List[Tuple[float, str, int]] = []
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None
        self._dns_domain_counter: Counter = Counter()
        self._dns_query_types: Counter = Counter()
        self._dns_response_codes: Counter = Counter()
        self._dns_queries: Dict[Tuple[str, int, int], float] = {}
        self._dns_rtt_samples: List[float] = []
        self._dns_packets: List[dict] = []
        self._dns_total_queries = 0
        self._dns_total_responses = 0

    def process_packet(self, packet: Packet):
        self._stats.total_packets += 1
        self._stats.total_bytes += packet.original_len

        if self._start_time is None or packet.timestamp < self._start_time:
            self._start_time = packet.timestamp
        if self._end_time is None or packet.timestamp > self._end_time:
            self._end_time = packet.timestamp

        if packet.ethernet:
            self._stats.ethernet_packets += 1

        proto = "OTHER"
        if packet.ipv4:
            self._stats.ipv4_packets += 1
            self._ip_counter[packet.ipv4.src_ip] += 1
            self._ip_counter[packet.ipv4.dst_ip] += 1

            if packet.ipv4.is_fragmented:
                self._stats.ip_fragments += 1

            proto = "IPV4"

        if packet.ipv6:
            self._stats.ipv6_packets += 1
            self._ip_counter[packet.ipv6.src_ip] += 1
            self._ip_counter[packet.ipv6.dst_ip] += 1
            proto = "IPV6"

        if packet.tcp:
            self._stats.tcp_packets += 1
            self._port_counter[packet.tcp.src_port] += 1
            self._port_counter[packet.tcp.dst_port] += 1
            proto = "TCP"

        if packet.udp:
            self._stats.udp_packets += 1
            self._port_counter[packet.udp.src_port] += 1
            self._port_counter[packet.udp.dst_port] += 1
            proto = "UDP"

        if packet.icmp:
            self._stats.icmp_packets += 1
            proto = "ICMP"

        self._timeline.append((packet.timestamp, proto, packet.original_len))

    def process_reassembled_ip(self, count: int = 1):
        self._stats.reassembled_ip += count

    def process_http_messages(self, messages: List[HTTPMessage]):
        for msg in messages:
            if msg.is_request:
                self._stats.http_requests += 1
            else:
                self._stats.http_responses += 1

    def get_top_ips(self, n: int = 10) -> List[Tuple[str, int]]:
        return self._ip_counter.most_common(n)

    def get_top_ports(self, n: int = 10) -> List[Tuple[int, int]]:
        return self._port_counter.most_common(n)

    def get_timeline(self) -> List[Tuple[float, str, int]]:
        return sorted(self._timeline, key=lambda x: x[0])

    def get_time_range(self) -> Tuple[Optional[float], Optional[float]]:
        return (self._start_time, self._end_time)

    def get_protocol_stats(self) -> ProtocolStats:
        return self._stats

    def process_dns_packet(self, packet: Packet, dns: DNSPacket):
        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "")
        src_port = packet.udp.src_port if packet.udp else 0
        dst_port = packet.udp.dst_port if packet.udp else 0

        packet_info = {
            "timestamp": packet.timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "transaction_id": dns.transaction_id,
            "is_response": dns.qr,
            "opcode": dns.opcode,
            "opcode_str": dns_opcode_to_str(dns.opcode),
            "rcode": dns.rcode,
            "rcode_str": dns_rcode_to_str(dns.rcode),
            "questions": [],
            "answers": [],
        }

        for q in dns.questions:
            packet_info["questions"].append({
                "qname": q.qname,
                "qtype": q.qtype,
                "qtype_str": dns_type_to_str(q.qtype),
                "qclass": q.qclass,
            })

        for ans in dns.answers:
            packet_info["answers"].append({
                "name": ans.name,
                "rtype": ans.rtype,
                "rtype_str": dns_type_to_str(ans.rtype),
                "rclass": ans.rclass,
                "ttl": ans.ttl,
                "rdata": ans.rdata,
            })

        self._dns_packets.append(packet_info)

        if not dns.qr:
            self._dns_total_queries += 1
            for q in dns.questions:
                if q.qname:
                    self._dns_domain_counter[q.qname] += 1
                self._dns_query_types[q.qtype] += 1

            query_key = (src_ip, dst_ip, dns.transaction_id)
            self._dns_queries[query_key] = packet.timestamp
        else:
            self._dns_total_responses += 1
            self._dns_response_codes[dns.rcode] += 1

            query_key = (dst_ip, src_ip, dns.transaction_id)
            if query_key in self._dns_queries:
                rtt = packet.timestamp - self._dns_queries[query_key]
                if rtt >= 0:
                    self._dns_rtt_samples.append(rtt)
                del self._dns_queries[query_key]

    def get_dns_stats(self) -> Optional[DNSStats]:
        if self._dns_total_queries == 0 and self._dns_total_responses == 0:
            return None

        rtt_min = 0.0
        rtt_max = 0.0
        rtt_avg = 0.0
        if self._dns_rtt_samples:
            rtt_min = min(self._dns_rtt_samples)
            rtt_max = max(self._dns_rtt_samples)
            rtt_avg = sum(self._dns_rtt_samples) / len(self._dns_rtt_samples)

        unanswered = len(self._dns_queries)

        return DNSStats(
            total_queries=self._dns_total_queries,
            total_responses=self._dns_total_responses,
            query_types=dict(self._dns_query_types),
            response_codes=dict(self._dns_response_codes),
            top_domains=self._dns_domain_counter.most_common(10),
            rtt_samples=self._dns_rtt_samples,
            rtt_min=rtt_min,
            rtt_max=rtt_max,
            rtt_avg=rtt_avg,
            unanswered_queries=unanswered,
            dns_packets=self._dns_packets,
        )

    def build_result(
        self,
        tcp_streams: Dict[Quadruple, TCPStream],
        http_messages: List[HTTPMessage],
        dns_stats: Optional[DNSStats] = None,
    ) -> AnalysisResult:
        return AnalysisResult(
            protocol_stats=self._stats,
            timeline=self.get_timeline(),
            top_ips=self.get_top_ips(10),
            top_ports=self.get_top_ports(10),
            tcp_streams=tcp_streams,
            http_messages=http_messages,
            dns_stats=dns_stats,
        )
