#!/usr/bin/env python3
import argparse
import sys
import time
from typing import List

from .core import (
    PcapParser,
    parse_packet,
    parse_tcp,
    parse_udp,
    parse_icmp,
    IPReassembler,
    TCPReassembler,
)
from .analytics import (
    Analyzer,
    to_json,
    print_summary,
    write_json_file,
    write_text_file,
)
from .extractors import HTTPExtractor
from .utils import Packet, ReassembledIPPacket, HTTPMessage
from .utils.constants import (
    IP_PROTO_TCP,
    IP_PROTO_UDP,
    IP_PROTO_ICMP,
    IP_PROTO_ICMPV6,
    LINKTYPE_ETHERNET,
)


def _process_reassembled_payload(
    packet: Packet,
    reassembled: ReassembledIPPacket,
    tcp_reassembler: TCPReassembler,
    analyzer: Analyzer,
) -> Packet:
    if reassembled.protocol == IP_PROTO_TCP:
        tcp_seg = parse_tcp(reassembled.payload)
        if tcp_seg:
            packet.tcp = tcp_seg
            tcp_reassembler.add_packet(packet)
    elif reassembled.protocol == IP_PROTO_UDP:
        udp_seg = parse_udp(reassembled.payload)
        if udp_seg:
            packet.udp = udp_seg
    elif reassembled.protocol in (IP_PROTO_ICMP, IP_PROTO_ICMPV6):
        icmp_pkt = parse_icmp(reassembled.payload)
        if icmp_pkt:
            packet.icmp = icmp_pkt

    analyzer.process_reassembled_ip(1)
    return packet


def _update_packet_from_reassembled(
    packet: Packet,
    reassembled: ReassembledIPPacket,
) -> Packet:
    if reassembled.protocol == IP_PROTO_TCP:
        tcp_seg = parse_tcp(reassembled.payload)
        if tcp_seg:
            packet.tcp = tcp_seg
    elif reassembled.protocol == IP_PROTO_UDP:
        udp_seg = parse_udp(reassembled.payload)
        if udp_seg:
            packet.udp = udp_seg
    elif reassembled.protocol in (IP_PROTO_ICMP, IP_PROTO_ICMPV6):
        icmp_pkt = parse_icmp(reassembled.payload)
        if icmp_pkt:
            packet.icmp = icmp_pkt
    return packet


def analyze_pcap(
    file_path: str,
    verbose: bool = False,
    progress_interval: int = 10000,
) -> tuple:
    ip_reassembler = IPReassembler(timeout=30.0)
    tcp_reassembler = TCPReassembler()
    analyzer = Analyzer()
    http_extractor = HTTPExtractor()
    all_http_messages: List[HTTPMessage] = []

    packet_count = 0
    start_time = time.time()

    with PcapParser(file_path, use_mmap=True) as parser:
        link_type = parser.file_info.link_type if parser.file_info else LINKTYPE_ETHERNET

        for raw_pkt in parser:
            packet = parse_packet(
                timestamp=raw_pkt.timestamp,
                captured_len=raw_pkt.captured_len,
                original_len=raw_pkt.original_len,
                link_type=link_type,
                data=raw_pkt.data,
            )

            if packet.ipv4 and packet.ipv4.is_fragmented:
                reassembled = ip_reassembler.add_fragment(packet.ipv4)
                if reassembled and reassembled.total_fragments > 1:
                    packet.tcp = None
                    packet.udp = None
                    packet.icmp = None
                    analyzer.process_packet(packet)
                    packet = _process_reassembled_payload(
                        packet, reassembled, tcp_reassembler, analyzer
                    )
                else:
                    if packet.ipv4.fragment_offset > 0:
                        packet.tcp = None
                        packet.udp = None
                        packet.icmp = None
                    analyzer.process_packet(packet)
            else:
                if packet.tcp:
                    tcp_reassembler.add_packet(packet)
                analyzer.process_packet(packet)

            packet_count += 1
            if verbose and packet_count % progress_interval == 0:
                elapsed = time.time() - start_time
                rate = packet_count / elapsed if elapsed > 0 else 0
                print(
                    f"Processed {packet_count:,} packets... "
                    f"({rate:,.0f} pkts/s, {elapsed:.2f}s)",
                    file=sys.stderr,
                )

    flushed_reassembled = ip_reassembler.flush()
    for reassembled in flushed_reassembled:
        if reassembled.total_fragments > 1:
            fake_packet = Packet(
                timestamp=0.0,
                captured_len=0,
                original_len=0,
                link_type=link_type,
                raw_payload=b"",
            )
            fake_packet = _update_packet_from_reassembled(fake_packet, reassembled)
            if fake_packet.tcp:
                tcp_reassembler.add_packet(fake_packet)
            analyzer.process_reassembled_ip(1)

    for stream in tcp_reassembler.get_all_streams().values():
        http_messages = http_extractor.extract_from_stream(stream)
        if http_messages:
            all_http_messages.extend(http_messages)
            analyzer.process_http_messages(http_messages)

    result = analyzer.build_result(
        tcp_streams=tcp_reassembler.get_all_streams(),
        http_messages=all_http_messages,
    )

    elapsed = time.time() - start_time
    stats = analyzer.get_protocol_stats()

    if verbose:
        print(
            f"\nCompleted: {packet_count:,} packets in {elapsed:.3f}s "
            f"({packet_count/elapsed:,.0f} pkts/s)",
            file=sys.stderr,
        )

    return result, packet_count, elapsed


def main():
    parser = argparse.ArgumentParser(
        description="PCAP/PCAPNG Network Protocol Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture.pcap
  %(prog)s capture.pcapng --json output.json
  %(prog)s capture.pcap --text output.txt --verbose
  %(prog)s capture.pcap --json output.json --text output.txt
        """,
    )

    parser.add_argument(
        "file",
        help="PCAP or PCAPNG file to analyze",
    )

    parser.add_argument(
        "--json",
        metavar="OUTPUT_FILE",
        help="Write analysis results to JSON file",
    )

    parser.add_argument(
        "--text",
        metavar="OUTPUT_FILE",
        help="Write analysis results to text file with ASCII tables",
    )

    parser.add_argument(
        "--no-stdout",
        action="store_true",
        help="Do not print results to stdout",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show progress and timing information",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0",
    )

    args = parser.parse_args()

    try:
        result, packet_count, elapsed = analyze_pcap(
            args.file,
            verbose=args.verbose,
        )

        if not args.no_stdout:
            print(print_summary(result))

        if args.json:
            write_json_file(result, args.json)
            if args.verbose:
                print(f"JSON results written to: {args.json}", file=sys.stderr)

        if args.text:
            write_text_file(result, args.text)
            if args.verbose:
                print(f"Text results written to: {args.text}", file=sys.stderr)

        if args.verbose:
            file_size = 0
            try:
                import os
                file_size = os.path.getsize(args.file)
            except OSError:
                pass

            throughput = (file_size / 1024 / 1024) / elapsed if elapsed > 0 and file_size > 0 else 0
            print(
                f"\nPerformance: {throughput:.2f} MB/s "
                f"({file_size/1024/1024:.2f} MB in {elapsed:.3f}s)",
                file=sys.stderr,
            )

        return 0

    except FileNotFoundError:
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
