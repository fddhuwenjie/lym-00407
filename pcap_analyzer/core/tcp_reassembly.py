from typing import Dict, Optional, List, Tuple
from collections import defaultdict

from ..utils import Packet, TCPStream, Quadruple
from ..utils.constants import TCP_FLAG_SYN, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_ACK
from .protocol_parser import get_quadruple, is_client_to_server


_UINT32_MASK = 0xFFFFFFFF


class TCPReassembler:
    def __init__(self):
        self._streams: Dict[Quadruple, TCPStream] = {}

    def add_packet(self, packet: Packet) -> Optional[Quadruple]:
        if packet.tcp is None:
            return None

        src_ip = None
        dst_ip = None
        if packet.ipv4:
            src_ip = packet.ipv4.src_ip
            dst_ip = packet.ipv4.dst_ip
        elif packet.ipv6:
            src_ip = packet.ipv6.src_ip
            dst_ip = packet.ipv6.dst_ip

        if src_ip is None or dst_ip is None:
            return None

        q = Quadruple(src_ip, packet.tcp.src_port, dst_ip, packet.tcp.dst_port)
        q_norm = self._normalize(q)

        if q_norm not in self._streams:
            self._streams[q_norm] = TCPStream(quadruple=q_norm)

        stream = self._streams[q_norm]
        self._process_segment(packet, stream, q)

        return q_norm

    def _normalize(self, q: Quadruple) -> Quadruple:
        if (q.src_ip, q.src_port) > (q.dst_ip, q.dst_port):
            return Quadruple(q.dst_ip, q.dst_port, q.src_ip, q.src_port)
        return q

    def _process_segment(self, packet: Packet, stream: TCPStream, q: Quadruple):
        tcp = packet.tcp
        flags = tcp.flags
        payload = tcp.payload
        seq_num = tcp.seq_num

        has_syn = bool(flags & TCP_FLAG_SYN)
        has_ack = bool(flags & TCP_FLAG_ACK)
        has_fin = bool(flags & TCP_FLAG_FIN)
        has_rst = bool(flags & TCP_FLAG_RST)

        if has_rst:
            stream.is_closed = True
            return

        if has_syn and not has_ack:
            if stream.client_quadruple is None:
                stream.client_quadruple = q

        is_client = (stream.client_quadruple is None and q == stream.quadruple) or q == stream.client_quadruple

        if has_syn:
            if is_client:
                if stream.client_seq_base is None:
                    stream.client_seq_base = (seq_num + 1) & _UINT32_MASK
                    return
            else:
                if stream.server_seq_base is None:
                    stream.server_seq_base = (seq_num + 1) & _UINT32_MASK
                    return

        if is_client:
            if stream.client_seq_base is None:
                stream.client_seq_base = seq_num
            rel_seq = (seq_num - stream.client_seq_base) & _UINT32_MASK
            buffered = stream.client_buffered
            target_data = bytearray(stream.client_to_server)
        else:
            if stream.server_seq_base is None:
                stream.server_seq_base = seq_num
            rel_seq = (seq_num - stream.server_seq_base) & _UINT32_MASK
            buffered = stream.server_buffered
            target_data = bytearray(stream.server_to_client)

        if payload:
            payload_len = len(payload)
            buffered[rel_seq] = payload

            expected_seq = len(target_data)
            while expected_seq in buffered:
                data = buffered[expected_seq]
                target_data.extend(data)
                del buffered[expected_seq]
                expected_seq += len(data)

            if is_client:
                stream.client_to_server = bytes(target_data)
            else:
                stream.server_to_client = bytes(target_data)

        if has_fin:
            if is_client:
                stream.client_fin = True
            else:
                stream.server_fin = True
            if stream.client_fin and stream.server_fin:
                stream.is_closed = True

    def get_stream(self, q: Quadruple) -> Optional[TCPStream]:
        q_norm = self._normalize(q)
        return self._streams.get(q_norm)

    def get_all_streams(self) -> Dict[Quadruple, TCPStream]:
        return dict(self._streams)

    def stream_count(self) -> int:
        return len(self._streams)

    def get_closed_streams(self) -> Dict[Quadruple, TCPStream]:
        return {q: s for q, s in self._streams.items() if s.is_closed}

    def get_stream_data(self, q: Quadruple) -> Tuple[bytes, bytes]:
        stream = self.get_stream(q)
        if stream is None:
            return (b"", b"")
        return (stream.client_to_server, stream.server_to_client)
