from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import namedtuple

Quadruple = namedtuple("Quadruple", ["src_ip", "src_port", "dst_ip", "dst_port"])


@dataclass
class EthernetFrame:
    dst_mac: str
    src_mac: str
    eth_type: int
    payload: bytes


@dataclass
class IPv4Packet:
    version: int
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    src_ip: str
    dst_ip: str
    options: bytes
    payload: bytes
    is_fragmented: bool = False
    more_fragments: bool = False


@dataclass
class IPv6Packet:
    version: int
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    src_ip: str
    dst_ip: str
    payload: bytes


@dataclass
class ICMPPacket:
    type: int
    code: int
    checksum: int
    identifier: int = 0
    sequence: int = 0
    payload: bytes = b""


@dataclass
class TCPSegment:
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    data_offset: int
    flags: int
    window_size: int
    checksum: int
    urgent_pointer: int
    options: bytes
    payload: bytes


@dataclass
class UDPSegment:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes


@dataclass
class Packet:
    timestamp: float
    captured_len: int
    original_len: int
    link_type: int
    ethernet: Optional[EthernetFrame] = None
    ipv4: Optional[IPv4Packet] = None
    ipv6: Optional[IPv6Packet] = None
    icmp: Optional[ICMPPacket] = None
    tcp: Optional[TCPSegment] = None
    udp: Optional[UDPSegment] = None
    raw_payload: bytes = b""


@dataclass(frozen=True)
class IPFragmentKey:
    src_ip: str
    dst_ip: str
    protocol: int
    identification: int


@dataclass
class IPFragment:
    offset: int
    more_fragments: bool
    payload: bytes


@dataclass
class ReassembledIPPacket:
    src_ip: str
    dst_ip: str
    protocol: int
    payload: bytes
    total_fragments: int


@dataclass
class TCPStream:
    quadruple: Quadruple
    client_to_server: bytes = b""
    server_to_client: bytes = b""
    client_seq_base: Optional[int] = None
    server_seq_base: Optional[int] = None
    client_buffered: Dict[int, bytes] = field(default_factory=dict)
    server_buffered: Dict[int, bytes] = field(default_factory=dict)
    is_closed: bool = False
    client_fin: bool = False
    server_fin: bool = False
    client_quadruple: Optional[Quadruple] = None


@dataclass
class HTTPMessage:
    is_request: bool
    method: Optional[str] = None
    path: Optional[str] = None
    version: Optional[str] = None
    status_code: Optional[int] = None
    status_phrase: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""


@dataclass
class ProtocolStats:
    total_packets: int = 0
    total_bytes: int = 0
    ethernet_packets: int = 0
    ipv4_packets: int = 0
    ipv6_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    http_requests: int = 0
    http_responses: int = 0
    ip_fragments: int = 0
    reassembled_ip: int = 0


@dataclass
class DNSQuestion:
    qname: str
    qtype: int
    qclass: int


@dataclass
class DNSResourceRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdlength: int
    rdata: str
    rdata_raw: bytes


@dataclass
class DNSPacket:
    transaction_id: int
    flags: int
    qr: bool
    opcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    questions: List[DNSQuestion]
    answers: List[DNSResourceRecord]
    authority: List[DNSResourceRecord]
    additional: List[DNSResourceRecord]


@dataclass
class DNSStats:
    total_queries: int = 0
    total_responses: int = 0
    query_types: Dict[int, int] = field(default_factory=dict)
    response_codes: Dict[int, int] = field(default_factory=dict)
    top_domains: List[Tuple[str, int]] = field(default_factory=list)
    rtt_samples: List[float] = field(default_factory=list)
    rtt_min: float = 0.0
    rtt_max: float = 0.0
    rtt_avg: float = 0.0
    unanswered_queries: int = 0
    dns_packets: List[dict] = field(default_factory=list)


@dataclass
class AnalysisResult:
    protocol_stats: ProtocolStats
    timeline: List[Tuple[float, str, int]]
    top_ips: List[Tuple[str, int]]
    top_ports: List[Tuple[int, int]]
    tcp_streams: Dict[Quadruple, TCPStream]
    http_messages: List[HTTPMessage]
    dns_stats: Optional[DNSStats] = None
