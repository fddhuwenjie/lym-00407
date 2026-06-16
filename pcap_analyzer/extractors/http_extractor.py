from typing import List, Dict, Optional, Tuple
import re

from ..utils import HTTPMessage, TCPStream


class HTTPExtractor:
    _HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT"}

    def __init__(self):
        self._requests: List[HTTPMessage] = []
        self._responses: List[HTTPMessage] = []

    def extract_from_stream(self, stream: TCPStream) -> List[HTTPMessage]:
        messages: List[HTTPMessage] = []

        request_msg, remaining = self._extract_requests(stream.client_to_server)
        messages.extend(request_msg)

        response_msg, remaining = self._extract_responses(stream.server_to_client)
        messages.extend(response_msg)

        return messages

    def _extract_requests(self, data: bytes) -> Tuple[List[HTTPMessage], bytes]:
        messages: List[HTTPMessage] = []
        pos = 0

        while pos < len(data):
            msg, consumed = self._parse_request(data[pos:])
            if msg is None:
                break
            messages.append(msg)
            pos += consumed

        remaining = data[pos:] if pos < len(data) else b""
        return messages, remaining

    def _extract_responses(self, data: bytes) -> Tuple[List[HTTPMessage], bytes]:
        messages: List[HTTPMessage] = []
        pos = 0

        while pos < len(data):
            msg, consumed = self._parse_response(data[pos:])
            if msg is None:
                break
            messages.append(msg)
            pos += consumed

        remaining = data[pos:] if pos < len(data) else b""
        return messages, remaining

    def _parse_request(self, data: bytes) -> Tuple[Optional[HTTPMessage], int]:
        header_end = data.find(b"\r\n\r\n")
        if header_end == -1:
            return None, 0

        header_data = data[:header_end]
        try:
            header_str = header_data.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return None, 0

        lines = header_str.split("\r\n")
        if not lines:
            return None, 0

        request_line = lines[0]
        parts = request_line.split(" ", 2)
        if len(parts) != 3:
            return None, 0

        method, path, version = parts
        if not method.isascii() or method.encode() not in self._HTTP_METHODS:
            return None, 0

        headers = self._parse_headers(lines[1:])

        body, body_len = self._parse_body(data[header_end + 4:], headers)

        total_consumed = header_end + 4 + body_len

        msg = HTTPMessage(
            is_request=True,
            method=method,
            path=path,
            version=version,
            headers=headers,
            body=body,
        )

        return msg, total_consumed

    def _parse_response(self, data: bytes) -> Tuple[Optional[HTTPMessage], int]:
        header_end = data.find(b"\r\n\r\n")
        if header_end == -1:
            return None, 0

        header_data = data[:header_end]
        try:
            header_str = header_data.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return None, 0

        lines = header_str.split("\r\n")
        if not lines:
            return None, 0

        status_line = lines[0]
        if not status_line.startswith("HTTP/"):
            return None, 0

        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            return None, 0

        version = parts[0]
        try:
            status_code = int(parts[1])
        except (ValueError, IndexError):
            return None, 0

        status_phrase = parts[2] if len(parts) > 2 else ""

        headers = self._parse_headers(lines[1:])

        body, body_len = self._parse_body(data[header_end + 4:], headers)

        total_consumed = header_end + 4 + body_len

        msg = HTTPMessage(
            is_request=False,
            version=version,
            status_code=status_code,
            status_phrase=status_phrase,
            headers=headers,
            body=body,
        )

        return msg, total_consumed

    def _parse_headers(self, lines: List[str]) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        current_key: Optional[str] = None

        for line in lines:
            if not line:
                continue

            if line[0] in (" ", "\t") and current_key:
                headers[current_key] += " " + line.strip()
            else:
                colon_pos = line.find(":")
                if colon_pos != -1:
                    key = line[:colon_pos].strip()
                    value = line[colon_pos + 1:].strip()
                    headers[key] = value
                    current_key = key

        return headers

    def _parse_body(self, data: bytes, headers: Dict[str, str]) -> Tuple[bytes, int]:
        transfer_encoding = headers.get("Transfer-Encoding", "").lower()
        content_length = headers.get("Content-Length")

        if "chunked" in transfer_encoding:
            return self._parse_chunked_body(data)
        elif content_length is not None:
            try:
                length = int(content_length)
                if length <= 0:
                    return b"", 0
                body = data[:length] if length <= len(data) else data
                return body, min(length, len(data))
            except (ValueError, TypeError):
                return b"", 0
        else:
            return b"", 0

    def _parse_chunked_body(self, data: bytes) -> Tuple[bytes, int]:
        body = bytearray()
        pos = 0

        while True:
            line_end = data.find(b"\r\n", pos)
            if line_end == -1:
                break

            size_line = data[pos:line_end].strip()
            if not size_line:
                pos = line_end + 2
                continue

            try:
                size_str = size_line.split(b";")[0].strip().decode("ascii")
                chunk_size = int(size_str, 16)
            except (ValueError, UnicodeDecodeError):
                break

            pos = line_end + 2

            if chunk_size == 0:
                if data[pos:pos + 2] == b"\r\n":
                    pos += 2
                break

            if pos + chunk_size > len(data):
                break

            body.extend(data[pos:pos + chunk_size])
            pos += chunk_size

            if data[pos:pos + 2] == b"\r\n":
                pos += 2
            else:
                break

        return bytes(body), pos

    def get_all_messages(self) -> List[HTTPMessage]:
        return self._requests + self._responses

    def get_requests(self) -> List[HTTPMessage]:
        return self._requests

    def get_responses(self) -> List[HTTPMessage]:
        return self._responses
