from typing import List, Dict, Tuple, Optional
from collections import defaultdict, Counter

from ..utils import (
    Packet,
    ProtocolStats,
    AnalysisResult,
    Quadruple,
    TCPStream,
    HTTPMessage,
)
from ..extractors import HTTPExtractor


class Analyzer:
    def __init__(self):
        self._stats = ProtocolStats()
        self._ip_counter: Counter = Counter()
        self._port_counter: Counter = Counter()
        self._timeline: List[Tuple[float, str, int]] = []
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None

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

    def build_result(
        self,
        tcp_streams: Dict[Quadruple, TCPStream],
        http_messages: List[HTTPMessage],
    ) -> AnalysisResult:
        return AnalysisResult(
            protocol_stats=self._stats,
            timeline=self.get_timeline(),
            top_ips=self.get_top_ips(10),
            top_ports=self.get_top_ports(10),
            tcp_streams=tcp_streams,
            http_messages=http_messages,
        )
