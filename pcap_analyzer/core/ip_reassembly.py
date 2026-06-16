from typing import Dict, Optional, List
import time

from ..utils import IPv4Packet, IPFragmentKey, IPFragment, ReassembledIPPacket


class IPReassembler:
    def __init__(self, timeout: float = 30.0):
        self._fragments: Dict[IPFragmentKey, Dict[int, IPFragment]] = {}
        self._last_seen: Dict[IPFragmentKey, float] = {}
        self._total_length: Dict[IPFragmentKey, int] = {}
        self._timeout = timeout

    def add_fragment(self, ipv4_pkt: IPv4Packet) -> Optional[ReassembledIPPacket]:
        if not ipv4_pkt.is_fragmented and ipv4_pkt.fragment_offset == 0:
            return ReassembledIPPacket(
                src_ip=ipv4_pkt.src_ip,
                dst_ip=ipv4_pkt.dst_ip,
                protocol=ipv4_pkt.protocol,
                payload=ipv4_pkt.payload,
                total_fragments=1,
            )

        key = IPFragmentKey(
            src_ip=ipv4_pkt.src_ip,
            dst_ip=ipv4_pkt.dst_ip,
            protocol=ipv4_pkt.protocol,
            identification=ipv4_pkt.identification,
        )

        now = time.time()
        self._last_seen[key] = now

        if key not in self._fragments:
            self._fragments[key] = {}
            self._total_length[key] = 0

        fragment = IPFragment(
            offset=ipv4_pkt.fragment_offset,
            more_fragments=ipv4_pkt.more_fragments,
            payload=ipv4_pkt.payload,
        )

        self._fragments[key][ipv4_pkt.fragment_offset] = fragment

        if not ipv4_pkt.more_fragments:
            self._total_length[key] = ipv4_pkt.fragment_offset + len(ipv4_pkt.payload)

        return self._try_reassemble(key)

    def _try_reassemble(self, key: IPFragmentKey) -> Optional[ReassembledIPPacket]:
        fragments = self._fragments.get(key)
        if not fragments:
            return None

        total_length = self._total_length.get(key, 0)
        if total_length == 0:
            return None

        sorted_offsets = sorted(fragments.keys())
        expected_offset = 0
        assembled = bytearray()

        for offset in sorted_offsets:
            if offset != expected_offset:
                return None

            frag = fragments[offset]
            assembled.extend(frag.payload)
            expected_offset = offset + len(frag.payload)

        if len(assembled) != total_length:
            return None

        result = ReassembledIPPacket(
            src_ip=key.src_ip,
            dst_ip=key.dst_ip,
            protocol=key.protocol,
            payload=bytes(assembled),
            total_fragments=len(fragments),
        )

        del self._fragments[key]
        del self._last_seen[key]
        if key in self._total_length:
            del self._total_length[key]

        return result

    def cleanup(self) -> int:
        now = time.time()
        expired_keys: List[IPFragmentKey] = []

        for key, last_seen in self._last_seen.items():
            if now - last_seen > self._timeout:
                expired_keys.append(key)

        for key in expired_keys:
            if key in self._fragments:
                del self._fragments[key]
            del self._last_seen[key]
            if key in self._total_length:
                del self._total_length[key]

        return len(expired_keys)

    def flush(self) -> List[ReassembledIPPacket]:
        results: List[ReassembledIPPacket] = []

        for key in list(self._fragments.keys()):
            result = self._try_reassemble(key)
            if result:
                results.append(result)

        return results

    def pending_count(self) -> int:
        return len(self._fragments)
