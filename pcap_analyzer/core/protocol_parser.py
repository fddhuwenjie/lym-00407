import struct
import socket
from typing import Optional, Tuple

from ..utils import (
    Packet,
    EthernetFrame,
    IPv4Packet,
    IPv6Packet,
    ICMPPacket,
    TCPSegment,
    UDPSegment,
    Quadruple,
)
from ..utils.constants import (
    ETH_TYPE_IPV4,
    ETH_TYPE_IPV6,
    ETH_TYPE_8021Q,
    ETH_TYPE_8021AD,
    IP_PROTO_ICMP,
    IP_PROTO_TCP,
    IP_PROTO_UDP,
    IP_PROTO_ICMPV6,
    IP6_EXT_HOP_BY_HOP,
    IP6_EXT_ROUTING,
    IP6_EXT_FRAGMENT,
    IP6_EXT_DEST_OPTS,
    IP6_EXT_NO_NEXT,
    IP6_EXT_AUTH,
)


def _mac_to_str(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _ipv4_to_str(ip_bytes: bytes) -> str:
    return ".".join(str(b) for b in ip_bytes)


def _ipv6_to_str(ip_bytes: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    except (socket.error, ValueError, OSError):
        return ":".join(f"{ip_bytes[i]:02x}{ip_bytes[i+1]:02x}" for i in range(0, 16, 2))


def parse_ethernet(data: bytes) -> Optional[EthernetFrame]:
    if len(data) < 14:
        return None

    dst_mac = data[0:6]
    src_mac = data[6:12]
    eth_type = struct.unpack(">H", data[12:14])[0]
    payload = data[14:]

    while eth_type in (ETH_TYPE_8021Q, ETH_TYPE_8021AD):
        if len(payload) < 4:
            break
        eth_type = struct.unpack(">H", payload[2:4])[0]
        payload = payload[4:]

    return EthernetFrame(
        dst_mac=_mac_to_str(dst_mac),
        src_mac=_mac_to_str(src_mac),
        eth_type=eth_type,
        payload=payload,
    )


def parse_ipv4(data: bytes) -> Optional[IPv4Packet]:
    if len(data) < 20:
        return None

    version_ihl = data[0]
    version = (version_ihl >> 4) & 0x0F
    if version != 4:
        return None

    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None

    tos = data[1]
    total_length = struct.unpack(">H", data[2:4])[0]
    identification = struct.unpack(">H", data[4:6])[0]
    flags_fragment = struct.unpack(">H", data[6:8])[0]
    ttl = data[8]
    protocol = data[9]
    checksum = struct.unpack(">H", data[10:12])[0]
    src_ip = _ipv4_to_str(data[12:16])
    dst_ip = _ipv4_to_str(data[16:20])
    options = data[20:ihl] if ihl > 20 else b""
    payload = data[ihl:]

    flags = (flags_fragment >> 13) & 0x07
    fragment_offset = (flags_fragment & 0x1FFF) * 8
    more_fragments = bool(flags & 0x01)
    is_fragmented = bool(flags & 0x01) or fragment_offset > 0

    return IPv4Packet(
        version=version,
        ihl=ihl,
        tos=tos,
        total_length=total_length,
        identification=identification,
        flags=flags,
        fragment_offset=fragment_offset,
        ttl=ttl,
        protocol=protocol,
        checksum=checksum,
        src_ip=src_ip,
        dst_ip=dst_ip,
        options=options,
        payload=payload,
        is_fragmented=is_fragmented,
        more_fragments=more_fragments,
    )


def _skip_ipv6_extension_headers(data: bytes, next_header: int) -> Tuple[int, bytes]:
    _EXT_HEADERS = frozenset({
        IP6_EXT_HOP_BY_HOP,
        IP6_EXT_ROUTING,
        IP6_EXT_FRAGMENT,
        IP6_EXT_DEST_OPTS,
        IP6_EXT_AUTH,
    })

    offset = 0
    current_nh = next_header

    while current_nh in _EXT_HEADERS and offset < len(data):
        if current_nh == IP6_EXT_AUTH:
            if offset + 2 > len(data):
                break
            hdr_len = (data[offset + 1] + 2) * 4
            current_nh = data[offset]
            offset += hdr_len
        elif current_nh == IP6_EXT_FRAGMENT:
            current_nh = data[offset]
            offset += 8
        else:
            if offset + 2 > len(data):
                break
            hdr_len = (data[offset + 1] + 1) * 8
            current_nh = data[offset]
            offset += hdr_len

    return current_nh, data[offset:]


def parse_ipv6(data: bytes) -> Optional[IPv6Packet]:
    if len(data) < 40:
        return None

    version_tc_fl = struct.unpack(">I", data[0:4])[0]
    version = (version_tc_fl >> 28) & 0x0F
    if version != 6:
        return None

    traffic_class = (version_tc_fl >> 20) & 0xFF
    flow_label = version_tc_fl & 0x000FFFFF
    payload_length = struct.unpack(">H", data[4:6])[0]
    next_header = data[6]
    hop_limit = data[7]
    src_ip = _ipv6_to_str(data[8:24])
    dst_ip = _ipv6_to_str(data[24:40])

    final_nh, payload = _skip_ipv6_extension_headers(data[40:], next_header)

    return IPv6Packet(
        version=version,
        traffic_class=traffic_class,
        flow_label=flow_label,
        payload_length=payload_length,
        next_header=final_nh,
        hop_limit=hop_limit,
        src_ip=src_ip,
        dst_ip=dst_ip,
        payload=payload,
    )


def parse_icmp(data: bytes) -> Optional[ICMPPacket]:
    if len(data) < 8:
        return None

    icmp_type = data[0]
    code = data[1]
    checksum = struct.unpack(">H", data[2:4])[0]

    identifier = 0
    sequence = 0
    if len(data) >= 8:
        identifier = struct.unpack(">H", data[4:6])[0]
        sequence = struct.unpack(">H", data[6:8])[0]

    payload = data[8:] if len(data) > 8 else b""

    return ICMPPacket(
        type=icmp_type,
        code=code,
        checksum=checksum,
        identifier=identifier,
        sequence=sequence,
        payload=payload,
    )


def parse_tcp(data: bytes) -> Optional[TCPSegment]:
    if len(data) < 20:
        return None

    src_port = struct.unpack(">H", data[0:2])[0]
    dst_port = struct.unpack(">H", data[2:4])[0]
    seq_num = struct.unpack(">I", data[4:8])[0]
    ack_num = struct.unpack(">I", data[8:12])[0]
    data_offset_reserved = data[12]
    data_offset = (data_offset_reserved >> 4) * 4
    flags = data[13]
    window_size = struct.unpack(">H", data[14:16])[0]
    checksum = struct.unpack(">H", data[16:18])[0]
    urgent_pointer = struct.unpack(">H", data[18:20])[0]
    options = data[20:data_offset] if data_offset > 20 else b""
    payload = data[data_offset:]

    return TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq_num=seq_num,
        ack_num=ack_num,
        data_offset=data_offset,
        flags=flags,
        window_size=window_size,
        checksum=checksum,
        urgent_pointer=urgent_pointer,
        options=options,
        payload=payload,
    )


def parse_udp(data: bytes) -> Optional[UDPSegment]:
    if len(data) < 8:
        return None

    src_port = struct.unpack(">H", data[0:2])[0]
    dst_port = struct.unpack(">H", data[2:4])[0]
    length = struct.unpack(">H", data[4:6])[0]
    checksum = struct.unpack(">H", data[6:8])[0]
    payload = data[8:]

    return UDPSegment(
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        checksum=checksum,
        payload=payload,
    )


def parse_packet(
    timestamp: float,
    captured_len: int,
    original_len: int,
    link_type: int,
    data: bytes,
) -> Packet:
    packet = Packet(
        timestamp=timestamp,
        captured_len=captured_len,
        original_len=original_len,
        link_type=link_type,
        raw_payload=data,
    )

    eth_frame = parse_ethernet(data)
    if eth_frame is None:
        return packet

    packet.ethernet = eth_frame

    if eth_frame.eth_type == ETH_TYPE_IPV4:
        ipv4_pkt = parse_ipv4(eth_frame.payload)
        if ipv4_pkt:
            packet.ipv4 = ipv4_pkt
            if not ipv4_pkt.is_fragmented or ipv4_pkt.fragment_offset == 0:
                _parse_transport_layer(packet, ipv4_pkt.src_ip, ipv4_pkt.dst_ip, ipv4_pkt.protocol, ipv4_pkt.payload)

    elif eth_frame.eth_type == ETH_TYPE_IPV6:
        ipv6_pkt = parse_ipv6(eth_frame.payload)
        if ipv6_pkt:
            packet.ipv6 = ipv6_pkt
            _parse_transport_layer(packet, ipv6_pkt.src_ip, ipv6_pkt.dst_ip, ipv6_pkt.next_header, ipv6_pkt.payload)

    return packet


def _parse_transport_layer(
    packet: Packet,
    src_ip: str,
    dst_ip: str,
    protocol: int,
    payload: bytes,
):
    if protocol == IP_PROTO_TCP:
        tcp_seg = parse_tcp(payload)
        if tcp_seg:
            packet.tcp = tcp_seg
    elif protocol == IP_PROTO_UDP:
        udp_seg = parse_udp(payload)
        if udp_seg:
            packet.udp = udp_seg
    elif protocol == IP_PROTO_ICMP or protocol == IP_PROTO_ICMPV6:
        icmp_pkt = parse_icmp(payload)
        if icmp_pkt:
            packet.icmp = icmp_pkt


def get_quadruple(packet: Packet) -> Optional[Quadruple]:
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None

    if packet.ipv4:
        src_ip = packet.ipv4.src_ip
        dst_ip = packet.ipv4.dst_ip
    elif packet.ipv6:
        src_ip = packet.ipv6.src_ip
        dst_ip = packet.ipv6.dst_ip

    if packet.tcp:
        src_port = packet.tcp.src_port
        dst_port = packet.tcp.dst_port
    elif packet.udp:
        src_port = packet.udp.src_port
        dst_port = packet.udp.dst_port

    if src_ip and dst_ip and src_port is not None and dst_port is not None:
        return Quadruple(src_ip, src_port, dst_ip, dst_port)
    return None


def get_normalized_quadruple(packet: Packet) -> Optional[Quadruple]:
    q = get_quadruple(packet)
    if q is None:
        return None
    if (q.src_ip, q.src_port) > (q.dst_ip, q.dst_port):
        return Quadruple(q.dst_ip, q.dst_port, q.src_ip, q.src_port)
    return q


def is_client_to_server(packet: Packet, stream_quadruple: Quadruple) -> bool:
    q = get_quadruple(packet)
    if q is None:
        return False
    return q == stream_quadruple
