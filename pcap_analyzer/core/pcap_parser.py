import struct
import mmap
from typing import Iterator, Tuple, Optional, BinaryIO
from dataclasses import dataclass

from ..utils.constants import (
    PCAP_MAGIC_LE,
    PCAP_MAGIC_BE,
    PCAPNG_MAGIC,
    BLOCK_TYPE_SECTION_HEADER,
    BLOCK_TYPE_INTERFACE_DESCRIPTION,
    BLOCK_TYPE_ENHANCED_PACKET,
    BLOCK_TYPE_PACKET,
    LINKTYPE_ETHERNET,
)


@dataclass
class PcapFileInfo:
    is_pcapng: bool
    link_type: int
    snap_len: int
    ts_resolution: int = 1_000_000


@dataclass
class RawPacket:
    timestamp: float
    captured_len: int
    original_len: int
    data: bytes


def _detect_format(f: BinaryIO) -> Tuple[bool, str, int]:
    magic = f.read(4)
    if len(magic) < 4:
        raise ValueError("Empty file or cannot read magic number")

    magic_num = struct.unpack("<I", magic)[0]
    if magic_num == PCAP_MAGIC_LE:
        return False, "<", 0
    elif magic_num == PCAP_MAGIC_BE:
        return False, ">", 0
    elif magic_num == PCAPNG_MAGIC:
        return True, "<", 0
    else:
        magic_num_be = struct.unpack(">I", magic)[0]
        if magic_num_be == PCAPNG_MAGIC:
            return True, ">", 0
    raise ValueError(f"Unknown file format, magic: {magic.hex()}")


def _parse_pcap_header(f: BinaryIO, endian: str) -> Tuple[int, int]:
    header_data = f.read(20)
    if len(header_data) < 20:
        raise ValueError("Invalid PCAP header")

    (
        version_major,
        version_minor,
        thiszone,
        sigfigs,
        snap_len,
        link_type,
    ) = struct.unpack(f"{endian}HHIIII", header_data)

    return link_type, snap_len


def _parse_pcap_packet(
    f: BinaryIO, endian: str, ts_resolution: int
) -> Optional[RawPacket]:
    header_data = f.read(16)
    if len(header_data) < 16:
        return None

    ts_sec, ts_usec, cap_len, orig_len = struct.unpack(f"{endian}IIII", header_data)

    packet_data = f.read(cap_len)
    if len(packet_data) < cap_len:
        return None

    timestamp = ts_sec + (ts_usec / ts_resolution)
    return RawPacket(timestamp, cap_len, orig_len, packet_data)


def _parse_pcapng_section(f: BinaryIO, endian: str) -> bool:
    block_total_len = struct.unpack(f"{endian}I", f.read(4))[0]
    if block_total_len < 16:
        return False

    bom = struct.unpack(f"{endian}I", f.read(4))[0]
    if bom == 0x1A2B3C4D:
        pass
    elif bom == 0x4D3C2B1A:
        endian = ">" if endian == "<" else "<"
    else:
        return False

    version_major, version_minor = struct.unpack(f"{endian}HH", f.read(4))
    section_len = struct.unpack(f"{endian}Q", f.read(8))[0]

    options_len = block_total_len - 28
    if options_len > 0:
        f.read(options_len)

    f.read(4)
    return True


def _parse_pcapng_interface(f: BinaryIO, endian: str) -> Tuple[int, int]:
    block_total_len = struct.unpack(f"{endian}I", f.read(4))[0]
    link_type, reserved = struct.unpack(f"{endian}HH", f.read(4))
    snap_len = struct.unpack(f"{endian}I", f.read(4))[0]

    options_len = block_total_len - 16
    ts_resolution = 1_000_000

    if options_len > 0:
        options_data = f.read(options_len)
        offset = 0
        while offset < len(options_data) - 4:
            opt_code, opt_len = struct.unpack_from(f"{endian}HH", options_data, offset)
            offset += 4
            if opt_code == 9 and opt_len >= 1:
                ts_resol_byte = options_data[offset]
                if ts_resol_byte & 0x80:
                    ts_resolution = 2 ** (ts_resol_byte & 0x7F)
                else:
                    ts_resolution = 10**ts_resol_byte
            offset += opt_len
            if (offset % 4) != 0:
                offset += 4 - (offset % 4)
            if opt_code == 0:
                break

    f.read(4)
    return link_type, snap_len


def _parse_pcapng_enhanced_packet(
    f: BinaryIO, endian: str, ts_resolution: int
) -> Optional[RawPacket]:
    block_total_len_data = f.read(4)
    if len(block_total_len_data) < 4:
        return None
    block_total_len = struct.unpack(f"{endian}I", block_total_len_data)[0]

    if block_total_len < 28:
        f.read(block_total_len - 4)
        return None

    interface_id = struct.unpack(f"{endian}I", f.read(4))[0]
    ts_high, ts_low = struct.unpack(f"{endian}II", f.read(8))
    timestamp = (ts_high << 32 | ts_low) / ts_resolution

    cap_len, orig_len = struct.unpack(f"{endian}II", f.read(8))

    data = f.read(cap_len)
    if len(data) < cap_len:
        return None

    pad_len = (4 - (cap_len % 4)) % 4
    if pad_len > 0:
        f.read(pad_len)

    options_len = block_total_len - 28 - cap_len - pad_len
    if options_len > 0:
        f.read(options_len)

    f.read(4)
    return RawPacket(timestamp, cap_len, orig_len, data)


def _parse_pcapng_packet(
    f: BinaryIO, endian: str, ts_resolution: int
) -> Optional[RawPacket]:
    block_total_len_data = f.read(4)
    if len(block_total_len_data) < 4:
        return None
    block_total_len = struct.unpack(f"{endian}I", block_total_len_data)[0]

    if block_total_len < 20:
        f.read(block_total_len - 4)
        return None

    interface_id = struct.unpack(f"{endian}H", f.read(2))[0]
    drops_count = struct.unpack(f"{endian}H", f.read(2))[0]
    ts_high, ts_low = struct.unpack(f"{endian}II", f.read(8))
    timestamp = (ts_high << 32 | ts_low) / ts_resolution

    cap_len, orig_len = struct.unpack(f"{endian}II", f.read(8))

    data = f.read(cap_len)
    if len(data) < cap_len:
        return None

    pad_len = (4 - (cap_len % 4)) % 4
    if pad_len > 0:
        f.read(pad_len)

    f.read(4)
    return RawPacket(timestamp, cap_len, orig_len, data)


def _parse_pcapng_block(
    f: BinaryIO,
    endian: str,
    ts_resolution: int,
    link_type: int,
    snap_len: int,
) -> Tuple[Optional[RawPacket], int, int, int]:
    block_type_data = f.read(4)
    if len(block_type_data) < 4:
        return None, link_type, snap_len, ts_resolution

    block_type = struct.unpack(f"{endian}I", block_type_data)[0]

    if block_type == BLOCK_TYPE_SECTION_HEADER:
        _parse_pcapng_section(f, endian)
        return None, link_type, snap_len, ts_resolution
    elif block_type == BLOCK_TYPE_INTERFACE_DESCRIPTION:
        lt, sl = _parse_pcapng_interface(f, endian)
        return None, lt, sl, ts_resolution
    elif block_type == BLOCK_TYPE_ENHANCED_PACKET:
        pkt = _parse_pcapng_enhanced_packet(f, endian, ts_resolution)
        return pkt, link_type, snap_len, ts_resolution
    elif block_type == BLOCK_TYPE_PACKET:
        pkt = _parse_pcapng_packet(f, endian, ts_resolution)
        return pkt, link_type, snap_len, ts_resolution
    else:
        block_total_len_data = f.read(4)
        if len(block_total_len_data) < 4:
            return None, link_type, snap_len, ts_resolution
        block_total_len = struct.unpack(f"{endian}I", block_total_len_data)[0]
        remaining = block_total_len - 8
        if remaining > 0:
            f.read(remaining)
        f.read(4)
        return None, link_type, snap_len, ts_resolution


class PcapParser:
    def __init__(self, file_path: str, use_mmap: bool = True):
        self.file_path = file_path
        self.use_mmap = use_mmap
        self._file: Optional[BinaryIO] = None
        self._mmap: Optional[mmap.mmap] = None
        self._pos = 0
        self._data: Optional[bytes] = None
        self.file_info: Optional[PcapFileInfo] = None

    def __enter__(self) -> "PcapParser":
        self._file = open(self.file_path, "rb")
        if self.use_mmap:
            try:
                self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
                self._data = self._mmap
            except (ValueError, OSError):
                self._data = self._file.read()
        else:
            self._data = self._file.read()

        self._parse_header()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._mmap is not None:
            self._mmap.close()
        if self._file is not None:
            self._file.close()

    def _parse_header(self):
        if self._data is None:
            raise ValueError("No data loaded")

        magic = self._data[0:4]
        self._pos = 4

        magic_num_le = struct.unpack("<I", magic)[0]
        magic_num_be = struct.unpack(">I", magic)[0]

        is_pcapng = False
        endian = "<"
        ts_resolution = 1_000_000
        link_type = LINKTYPE_ETHERNET
        snap_len = 65535

        if magic_num_le == PCAP_MAGIC_LE:
            is_pcapng = False
            endian = "<"
        elif magic_num_be == PCAP_MAGIC_BE:
            is_pcapng = False
            endian = ">"
        elif magic_num_le == PCAPNG_MAGIC or magic_num_be == PCAPNG_MAGIC:
            is_pcapng = True
            endian = "<" if magic_num_le == PCAPNG_MAGIC else ">"
        else:
            raise ValueError(f"Unknown file format, magic: {magic.hex()}")

        if is_pcapng:
            link_type, snap_len, ts_resolution, endian = self._parse_pcapng_header(endian)
        else:
            link_type, snap_len = self._parse_pcap_header(endian)

        self.file_info = PcapFileInfo(is_pcapng, link_type, snap_len, ts_resolution)
        self._endian = endian

    def _parse_pcap_header(self, endian: str) -> Tuple[int, int]:
        if self._data is None:
            raise ValueError("No data loaded")

        header_data = self._data[self._pos : self._pos + 20]
        self._pos += 20

        (
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snap_len,
            link_type,
        ) = struct.unpack(f"{endian}HHIIII", header_data)

        return link_type, snap_len

    def _parse_pcapng_header(self, endian: str) -> Tuple[int, int, int, str]:
        if self._data is None:
            raise ValueError("No data loaded")

        link_type = LINKTYPE_ETHERNET
        snap_len = 65535
        ts_resolution = 1_000_000
        found_interface = False

        while self._pos < len(self._data) and not found_interface:
            block_type = struct.unpack_from(f"{endian}I", self._data, self._pos)[0]
            block_total_len = struct.unpack_from(f"{endian}I", self._data, self._pos + 4)[0]

            if block_type == BLOCK_TYPE_SECTION_HEADER:
                bom = struct.unpack_from(f"{endian}I", self._data, self._pos + 8)[0]
                if bom == 0x4D3C2B1A:
                    endian = ">" if endian == "<" else "<"
                self._pos += block_total_len
            elif block_type == BLOCK_TYPE_INTERFACE_DESCRIPTION:
                link_type = struct.unpack_from(f"{endian}H", self._data, self._pos + 8)[0]
                snap_len = struct.unpack_from(f"{endian}I", self._data, self._pos + 12)[0]

                ts_resol_offset = self._pos + 16
                while ts_resol_offset < self._pos + block_total_len - 4:
                    opt_code, opt_len = struct.unpack_from(
                        f"{endian}HH", self._data, ts_resol_offset
                    )
                    ts_resol_offset += 4
                    if opt_code == 9 and opt_len >= 1:
                        ts_resol_byte = self._data[ts_resol_offset]
                        if ts_resol_byte & 0x80:
                            ts_resolution = 2 ** (ts_resol_byte & 0x7F)
                        else:
                            ts_resolution = 10**ts_resol_byte
                    ts_resol_offset += opt_len
                    if (ts_resol_offset % 4) != 0:
                        ts_resol_offset += 4 - (ts_resol_offset % 4)
                    if opt_code == 0:
                        break

                found_interface = True
                self._pos += block_total_len
            else:
                break

        return link_type, snap_len, ts_resolution, endian

    def __iter__(self) -> Iterator[RawPacket]:
        if self._data is None or self.file_info is None:
            return

        endian = self._endian
        ts_resolution = self.file_info.ts_resolution

        if not self.file_info.is_pcapng:
            while self._pos < len(self._data) - 16:
                ts_sec, ts_usec, cap_len, orig_len = struct.unpack_from(
                    f"{endian}IIII", self._data, self._pos
                )
                self._pos += 16

                if cap_len <= 0 or self._pos + cap_len > len(self._data):
                    break

                packet_data = self._data[self._pos : self._pos + cap_len]
                self._pos += cap_len

                timestamp = ts_sec + (ts_usec / ts_resolution)
                yield RawPacket(timestamp, cap_len, orig_len, packet_data)
        else:
            while self._pos < len(self._data) - 8:
                block_type = struct.unpack_from(f"{endian}I", self._data, self._pos)[0]
                block_total_len = struct.unpack_from(
                    f"{endian}I", self._data, self._pos + 4
                )[0]

                if block_total_len <= 0 or self._pos + block_total_len > len(self._data):
                    break

                if block_type == BLOCK_TYPE_ENHANCED_PACKET and block_total_len >= 28:
                    ts_high = struct.unpack_from(f"{endian}I", self._data, self._pos + 12)[0]
                    ts_low = struct.unpack_from(f"{endian}I", self._data, self._pos + 16)[0]
                    cap_len = struct.unpack_from(f"{endian}I", self._data, self._pos + 20)[0]
                    orig_len = struct.unpack_from(f"{endian}I", self._data, self._pos + 24)[0]

                    timestamp = (ts_high << 32 | ts_low) / ts_resolution
                    packet_data = self._data[self._pos + 28 : self._pos + 28 + cap_len]

                    if len(packet_data) == cap_len:
                        yield RawPacket(timestamp, cap_len, orig_len, packet_data)

                elif block_type == BLOCK_TYPE_PACKET and block_total_len >= 20:
                    ts_high = struct.unpack_from(f"{endian}I", self._data, self._pos + 8)[0]
                    ts_low = struct.unpack_from(f"{endian}I", self._data, self._pos + 12)[0]
                    cap_len = struct.unpack_from(f"{endian}I", self._data, self._pos + 16)[0]
                    orig_len = struct.unpack_from(f"{endian}I", self._data, self._pos + 20)[0]

                    timestamp = (ts_high << 32 | ts_low) / ts_resolution
                    packet_data = self._data[self._pos + 24 : self._pos + 24 + cap_len]

                    if len(packet_data) == cap_len:
                        yield RawPacket(timestamp, cap_len, orig_len, packet_data)

                elif block_type == BLOCK_TYPE_INTERFACE_DESCRIPTION:
                    ts_resol_offset = self._pos + 16
                    while ts_resol_offset < self._pos + block_total_len - 4:
                        opt_code, opt_len = struct.unpack_from(
                            f"{endian}HH", self._data, ts_resol_offset
                        )
                        ts_resol_offset += 4
                        if opt_code == 9 and opt_len >= 1:
                            ts_resol_byte = self._data[ts_resol_offset]
                            if ts_resol_byte & 0x80:
                                ts_resolution = 2 ** (ts_resol_byte & 0x7F)
                            else:
                                ts_resolution = 10**ts_resol_byte
                        ts_resol_offset += opt_len
                        if (ts_resol_offset % 4) != 0:
                            ts_resol_offset += 4 - (ts_resol_offset % 4)
                        if opt_code == 0:
                            break

                self._pos += block_total_len


def parse_pcap(file_path: str) -> Iterator[RawPacket]:
    with PcapParser(file_path) as parser:
        for packet in parser:
            yield packet
