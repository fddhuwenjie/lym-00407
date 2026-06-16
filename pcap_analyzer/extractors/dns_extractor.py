import struct
import socket
from typing import Optional, Tuple, List

from ..utils import DNSPacket, DNSQuestion, DNSResourceRecord

DNS_TYPE_A = 1
DNS_TYPE_NS = 2
DNS_TYPE_CNAME = 5
DNS_TYPE_SOA = 6
DNS_TYPE_PTR = 12
DNS_TYPE_MX = 15
DNS_TYPE_TXT = 16
DNS_TYPE_AAAA = 28

DNS_CLASS_IN = 1

DNS_RCODE_NOERROR = 0
DNS_RCODE_FORMERR = 1
DNS_RCODE_SERVFAIL = 2
DNS_RCODE_NXDOMAIN = 3
DNS_RCODE_NOTIMP = 4
DNS_RCODE_REFUSED = 5


def _parse_domain_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    original_offset = offset
    jumped = False
    max_jumps = 10
    jumps = 0

    while offset < len(data):
        length = data[offset]

        if length == 0:
            offset += 1
            break

        if (length & 0xC0) == 0xC0:
            if offset + 2 > len(data):
                break
            if jumped:
                offset += 2
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer >= len(data):
                break
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                break
            continue

        offset += 1
        if offset + length > len(data):
            break
        label = data[offset:offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length

    result = ".".join(labels) if labels else ""
    final_offset = original_offset if jumped else offset
    return result, final_offset


def _parse_rdata(rtype: int, rdata_raw: bytes, data: bytes, rdata_offset: int) -> str:
    if rtype == DNS_TYPE_A and len(rdata_raw) == 4:
        try:
            return socket.inet_ntop(socket.AF_INET, rdata_raw)
        except (socket.error, ValueError):
            return ""
    elif rtype == DNS_TYPE_AAAA and len(rdata_raw) == 16:
        try:
            return socket.inet_ntop(socket.AF_INET6, rdata_raw)
        except (socket.error, ValueError):
            return ""
    elif rtype == DNS_TYPE_CNAME:
        name, _ = _parse_domain_name(data, rdata_offset)
        return name
    elif rtype == DNS_TYPE_NS:
        name, _ = _parse_domain_name(data, rdata_offset)
        return name
    elif rtype == DNS_TYPE_PTR:
        name, _ = _parse_domain_name(data, rdata_offset)
        return name
    elif rtype == DNS_TYPE_MX and len(rdata_raw) >= 2:
        preference = struct.unpack(">H", rdata_raw[:2])[0]
        exchange, _ = _parse_domain_name(data, rdata_offset + 2)
        return f"{preference} {exchange}"
    elif rtype == DNS_TYPE_TXT:
        parts = []
        pos = 0
        while pos < len(rdata_raw):
            txt_len = rdata_raw[pos]
            pos += 1
            if pos + txt_len <= len(rdata_raw):
                parts.append(rdata_raw[pos:pos + txt_len].decode("ascii", errors="replace"))
                pos += txt_len
            else:
                break
        return " ".join(parts)
    else:
        return rdata_raw.hex()


def _parse_resource_record(data: bytes, offset: int) -> Tuple[Optional[DNSResourceRecord], int]:
    if offset + 2 > len(data):
        return None, offset

    name, offset = _parse_domain_name(data, offset)

    if offset + 10 > len(data):
        return None, offset

    rtype = struct.unpack(">H", data[offset:offset + 2])[0]
    rclass = struct.unpack(">H", data[offset + 2:offset + 4])[0]
    ttl = struct.unpack(">I", data[offset + 4:offset + 8])[0]
    rdlength = struct.unpack(">H", data[offset + 8:offset + 10])[0]
    offset += 10

    if offset + rdlength > len(data):
        return None, offset

    rdata_raw = data[offset:offset + rdlength]
    rdata = _parse_rdata(rtype, rdata_raw, data, offset)
    offset += rdlength

    rr = DNSResourceRecord(
        name=name,
        rtype=rtype,
        rclass=rclass,
        ttl=ttl,
        rdlength=rdlength,
        rdata=rdata,
        rdata_raw=rdata_raw,
    )
    return rr, offset


def parse_dns(data: bytes) -> Optional[DNSPacket]:
    if len(data) < 12:
        return None

    transaction_id = struct.unpack(">H", data[0:2])[0]
    flags = struct.unpack(">H", data[2:4])[0]
    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]
    nscount = struct.unpack(">H", data[8:10])[0]
    arcount = struct.unpack(">H", data[10:12])[0]

    if qdcount > 100 or ancount > 100 or nscount > 100 or arcount > 100:
        return None

    opcode = (flags >> 11) & 0xF
    if opcode > 5:
        return None

    rcode = flags & 0xF
    if rcode > 10:
        return None

    qr = bool((flags >> 15) & 0x1)
    aa = bool((flags >> 10) & 0x1)
    tc = bool((flags >> 9) & 0x1)
    rd = bool((flags >> 8) & 0x1)
    ra = bool((flags >> 7) & 0x1)
    z = (flags >> 4) & 0x7
    rcode = flags & 0xF

    offset = 12

    questions: List[DNSQuestion] = []
    for _ in range(qdcount):
        if offset >= len(data):
            break
        qname, offset = _parse_domain_name(data, offset)
        if offset + 4 > len(data):
            break
        qtype = struct.unpack(">H", data[offset:offset + 2])[0]
        qclass = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        offset += 4
        questions.append(DNSQuestion(qname=qname, qtype=qtype, qclass=qclass))

    answers: List[DNSResourceRecord] = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        rr, offset = _parse_resource_record(data, offset)
        if rr is not None:
            answers.append(rr)

    authority: List[DNSResourceRecord] = []
    for _ in range(nscount):
        if offset >= len(data):
            break
        rr, offset = _parse_resource_record(data, offset)
        if rr is not None:
            authority.append(rr)

    additional: List[DNSResourceRecord] = []
    for _ in range(arcount):
        if offset >= len(data):
            break
        rr, offset = _parse_resource_record(data, offset)
        if rr is not None:
            additional.append(rr)

    return DNSPacket(
        transaction_id=transaction_id,
        flags=flags,
        qr=qr,
        opcode=opcode,
        aa=aa,
        tc=tc,
        rd=rd,
        ra=ra,
        z=z,
        rcode=rcode,
        qdcount=qdcount,
        ancount=ancount,
        nscount=nscount,
        arcount=arcount,
        questions=questions,
        answers=answers,
        authority=authority,
        additional=additional,
    )


def dns_type_to_str(qtype: int) -> str:
    types = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        41: "OPT",
    }
    return types.get(qtype, f"TYPE{qtype}")


def dns_rcode_to_str(rcode: int) -> str:
    rcodes = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
        6: "YXDOMAIN",
        7: "YXRRSET",
        8: "NXRRSET",
        9: "NOTAUTH",
        10: "NOTZONE",
    }
    return rcodes.get(rcode, f"RCODE{rcode}")


def dns_opcode_to_str(opcode: int) -> str:
    opcodes = {
        0: "QUERY",
        1: "IQUERY",
        2: "STATUS",
        4: "NOTIFY",
        5: "UPDATE",
    }
    return opcodes.get(opcode, f"OPCODE{opcode}")
