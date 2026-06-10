"""
PCAP Plugin — parses PCAP and PCAPNG packet capture files.

Extracts per-packet events with network metadata, protocol dissection for
DNS, HTTP, and TLS (SNI), plus connection summary statistics.

Requires: dpkt>=1.9.8
"""

from __future__ import annotations

import socket
import struct
import uuid
from collections import defaultdict
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import dpkt

    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

from babel.base_plugin import BasePlugin, PluginContext, PluginFatalError, PluginParseError

# Maximum number of packets before sampling kicks in
MAX_PACKETS_BEFORE_SAMPLING = 500_000

# Payload preview length (hex-encoded bytes)
PAYLOAD_PREVIEW_BYTES = 128

# PCAPNG magic bytes (Section Header Block)
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# TCP flag bit names
_TCP_FLAGS = (
    [
        (dpkt.tcp.TH_FIN, "FIN"),
        (dpkt.tcp.TH_SYN, "SYN"),
        (dpkt.tcp.TH_RST, "RST"),
        (dpkt.tcp.TH_PUSH, "PSH"),
        (dpkt.tcp.TH_ACK, "ACK"),
        (dpkt.tcp.TH_URG, "URG"),
        (dpkt.tcp.TH_ECE, "ECE"),
        (dpkt.tcp.TH_CWR, "CWR"),
    ]
    if DPKT_AVAILABLE
    else []
)

# Well-known protocol numbers
_PROTO_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-encap",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


def _format_flags(flags: int) -> str:
    """Return a comma-separated string of TCP flag mnemonics."""
    names = [name for bit, name in _TCP_FLAGS if flags & bit]
    return ",".join(names) if names else ""


def _inet_to_str(addr: bytes) -> str:
    """Convert binary IP address to human-readable string (IPv4 or IPv6)."""
    try:
        if len(addr) == 4:
            return socket.inet_ntop(socket.AF_INET, addr)
        elif len(addr) == 16:
            return socket.inet_ntop(socket.AF_INET6, addr)
    except (ValueError, OSError):
        pass
    return addr.hex()


def _ts_to_iso(ts: float) -> str:
    """Convert a packet epoch timestamp to ISO-8601 UTC string."""
    try:
        dt = datetime.fromtimestamp(ts, tz=UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (ValueError, OverflowError, OSError):
        return ""


def _payload_hex(data: bytes, max_bytes: int = PAYLOAD_PREVIEW_BYTES) -> str:
    """Return hex-encoded preview of payload bytes."""
    if not data:
        return ""
    return data[:max_bytes].hex()


def _is_pcapng(file_path: Path) -> bool:
    """Detect whether a file is PCAPNG format by magic bytes or extension."""
    if file_path.suffix.lower() == ".pcapng":
        return True
    try:
        with open(file_path, "rb") as fh:
            magic = fh.read(4)
            return magic == _PCAPNG_MAGIC
    except OSError:
        return False


class PcapPlugin(BasePlugin):
    """Parses PCAP/PCAPNG packet capture files using dpkt."""

    PLUGIN_NAME = "pcap"
    PLUGIN_VERSION = "1.0.0"
    DEFAULT_ARTIFACT_TYPE = "network"
    SUPPORTED_EXTENSIONS = [".pcap", ".pcapng", ".cap"]
    SUPPORTED_MIME_TYPES = ["application/vnd.tcpdump.pcap"]

    def __init__(self, context: PluginContext) -> None:
        super().__init__(context)
        self._packets_total = 0
        self._packets_parsed = 0
        self._packets_skipped = 0
        self._packets_sampled = 0
        self._sample_rate = 1  # 1 = no sampling
        self._protocol_counts: dict[str, int] = defaultdict(int)
        self._connection_pairs: dict[str, int] = defaultdict(int)
        self._dns_queries: int = 0
        self._http_requests: int = 0
        self._tls_handshakes: int = 0
        self._fh = None

    def setup(self) -> None:
        if not DPKT_AVAILABLE:
            raise PluginFatalError("dpkt is not installed. Run: pip install dpkt>=1.9.8")

    def teardown(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def parse(self) -> Generator[dict[str, Any], None, None]:
        file_path = self.ctx.source_file_path
        is_pcapng = _is_pcapng(file_path)

        try:
            self._fh = open(file_path, "rb")
        except OSError as exc:
            raise PluginFatalError(f"Cannot open capture file: {exc}") from exc

        try:
            if is_pcapng:
                reader = dpkt.pcapng.Reader(self._fh)
            else:
                reader = dpkt.pcap.Reader(self._fh)
        except Exception as exc:
            raise PluginFatalError(
                f"Cannot parse capture file (format={'pcapng' if is_pcapng else 'pcap'}): {exc}"
            ) from exc

        # First pass: count packets to decide sampling rate (only for large files)
        # We do a pre-scan by checking file size as a heuristic
        file_size = file_path.stat().st_size
        # Rough estimate: average packet ~200 bytes on disk including headers
        estimated_packets = file_size // 200
        if estimated_packets > MAX_PACKETS_BEFORE_SAMPLING:
            # Count exact number of packets for sampling decision
            packet_count = self._count_packets(file_path, is_pcapng)
            if packet_count > MAX_PACKETS_BEFORE_SAMPLING:
                self._sample_rate = max(1, packet_count // MAX_PACKETS_BEFORE_SAMPLING)
                self.log.info(
                    "Large capture detected (%d packets). Sampling every %d packets.",
                    packet_count,
                    self._sample_rate,
                )
            # Re-open and re-create reader after counting
            self._fh.close()
            self._fh = open(file_path, "rb")
            if is_pcapng:
                reader = dpkt.pcapng.Reader(self._fh)
            else:
                reader = dpkt.pcap.Reader(self._fh)

        for ts, buf in reader:
            self._packets_total += 1

            # Apply sampling
            if self._sample_rate > 1 and (self._packets_total % self._sample_rate) != 0:
                self._packets_sampled += 1
                continue

            try:
                event = self._parse_packet(ts, buf)
                if event is not None:
                    self._packets_parsed += 1
                    yield event
            except PluginParseError:
                self._packets_skipped += 1
            except Exception as exc:
                self._packets_skipped += 1
                self.log.debug("Skipped packet %d: %s", self._packets_total, exc)

    def _count_packets(self, file_path: Path, is_pcapng: bool) -> int:
        """Fast packet count without full parsing."""
        count = 0
        try:
            with open(file_path, "rb") as fh:
                if is_pcapng:
                    rdr = dpkt.pcapng.Reader(fh)
                else:
                    rdr = dpkt.pcap.Reader(fh)
                for _ in rdr:
                    count += 1
        except Exception:
            pass
        return count

    def _parse_packet(self, ts: float, buf: bytes) -> dict[str, Any] | None:
        """Parse a single packet buffer and return a normalized event dict."""
        timestamp = _ts_to_iso(ts)
        if not timestamp:
            raise PluginParseError("Invalid timestamp")

        packet_size = len(buf)

        # Try to decode as Ethernet first
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except (dpkt.UnpackError, Exception):
            # Could be raw IP (e.g., loopback captures)
            return self._parse_raw_ip(ts, buf, timestamp, packet_size)

        # Extract IP layer
        ip_pkt = eth.data
        if isinstance(ip_pkt, dpkt.ip.IP):
            return self._parse_ip_packet(timestamp, ip_pkt, packet_size, 4)
        elif isinstance(ip_pkt, dpkt.ip6.IP6):
            return self._parse_ip_packet(timestamp, ip_pkt, packet_size, 6)
        else:
            # Non-IP packet (ARP, etc.)
            ethertype = eth.type
            proto_name = {
                0x0806: "ARP",
                0x8100: "VLAN",
                0x86DD: "IPv6",
                0x88CC: "LLDP",
            }.get(ethertype, f"EtherType-0x{ethertype:04x}")

            self._protocol_counts[proto_name] += 1
            return {
                "fo_id": str(uuid.uuid4()),
                "artifact_type": "network",
                "timestamp": timestamp,
                "timestamp_desc": "Packet Capture Time",
                "message": f"{proto_name} ({packet_size} bytes)",
                "network": {
                    "protocol": proto_name,
                    "packet_size": packet_size,
                },
            }

    def _parse_raw_ip(
        self, ts: float, buf: bytes, timestamp: str, packet_size: int
    ) -> dict[str, Any] | None:
        """Attempt to parse buffer as raw IP (no Ethernet header)."""
        if not buf:
            return None

        version = (buf[0] >> 4) & 0xF
        try:
            if version == 4:
                ip_pkt = dpkt.ip.IP(buf)
                return self._parse_ip_packet(timestamp, ip_pkt, packet_size, 4)
            elif version == 6:
                ip_pkt = dpkt.ip6.IP6(buf)
                return self._parse_ip_packet(timestamp, ip_pkt, packet_size, 6)
        except (dpkt.UnpackError, Exception):
            pass

        raise PluginParseError("Cannot decode packet as Ethernet or raw IP")

    def _parse_ip_packet(
        self,
        timestamp: str,
        ip_pkt: Any,
        packet_size: int,
        ip_version: int,
    ) -> dict[str, Any]:
        """Parse an IP (v4 or v6) packet and its transport layer."""
        if ip_version == 4:
            src_ip = _inet_to_str(ip_pkt.src)
            dst_ip = _inet_to_str(ip_pkt.dst)
            proto_num = ip_pkt.p
        else:
            src_ip = _inet_to_str(ip_pkt.src)
            dst_ip = _inet_to_str(ip_pkt.dst)
            proto_num = ip_pkt.nxt

        proto_name = _PROTO_NAMES.get(proto_num, f"IP-{proto_num}")
        self._protocol_counts[proto_name] += 1

        transport = ip_pkt.data
        src_port = None
        dst_port = None
        flags_str = ""
        payload = b""

        # DNS / HTTP / TLS enrichment
        dns_info: dict[str, Any] | None = None
        http_info: dict[str, Any] | None = None
        tls_info: dict[str, Any] | None = None

        if isinstance(transport, dpkt.tcp.TCP):
            src_port = transport.sport
            dst_port = transport.dport
            flags_str = _format_flags(transport.flags)
            payload = bytes(transport.data)

            # HTTP detection (ports 80, 8080, or data starts with HTTP method)
            http_info = self._try_parse_http(payload)
            if http_info:
                self._http_requests += 1

            # TLS detection (port 443 or ClientHello)
            if not http_info:
                tls_info = self._try_parse_tls(payload)
                if tls_info:
                    self._tls_handshakes += 1

            # DNS over TCP (port 53)
            if dst_port == 53 or src_port == 53:
                dns_info = self._try_parse_dns_tcp(payload)
                if dns_info:
                    self._dns_queries += 1

        elif isinstance(transport, dpkt.udp.UDP):
            src_port = transport.sport
            dst_port = transport.dport
            payload = bytes(transport.data)

            # DNS detection (port 53)
            if dst_port == 53 or src_port == 53:
                dns_info = self._try_parse_dns(payload)
                if dns_info:
                    self._dns_queries += 1

        elif isinstance(transport, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
            payload = bytes(transport.data) if hasattr(transport, "data") else b""

        # Track connection pairs
        conn_key = f"{src_ip}->{dst_ip}:{proto_name}"
        self._connection_pairs[conn_key] += 1

        # Build message
        message = self._build_message(
            proto_name,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            flags_str,
            packet_size,
            dns_info,
            http_info,
            tls_info,
        )

        # Build network sub-object
        network: dict[str, Any] = {
            "protocol": proto_name,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "packet_size": packet_size,
            "ip_version": ip_version,
        }
        if src_port is not None:
            network["src_port"] = src_port
        if dst_port is not None:
            network["dst_port"] = dst_port
        if flags_str:
            network["flags"] = flags_str
        if payload:
            network["payload_preview"] = _payload_hex(payload)

        # Build the event
        event: dict[str, Any] = {
            "fo_id": str(uuid.uuid4()),
            "artifact_type": "network",
            "timestamp": timestamp,
            "timestamp_desc": "Packet Capture Time",
            "message": message,
            "network": network,
        }

        # Add protocol-specific enrichments
        if dns_info:
            event["dns"] = dns_info
        if http_info:
            # Map pcap http fields to standard schema
            event["http"] = {
                "method": http_info.get("method", ""),
                "request_path": http_info.get("path", ""),
                "protocol": http_info.get("version", ""),
                "status_code": 0,
                "response_size": int(http_info.get("content_length", 0) or 0),
                "referer": "",
                "user_agent": http_info.get("user_agent", ""),
            }
        if tls_info:
            event["tls"] = tls_info

        return event

    def _build_message(
        self,
        proto: str,
        src_ip: str,
        src_port: int | None,
        dst_ip: str,
        dst_port: int | None,
        flags: str,
        size: int,
        dns_info: dict | None,
        http_info: dict | None,
        tls_info: dict | None,
    ) -> str:
        """Build a human-readable summary message for the packet."""
        # DNS message
        if dns_info:
            qname = dns_info.get("query_name", "")
            qtype = dns_info.get("query_type", "")
            answers = dns_info.get("answers", [])
            if answers:
                ans_str = ", ".join(str(a) for a in answers[:3])
                return f"DNS {qtype} {qname} -> {ans_str} ({size} bytes)"
            return f"DNS {qtype} {qname} ({size} bytes)"

        # HTTP message
        if http_info:
            method = http_info.get("method", "")
            host = http_info.get("host", "")
            path = http_info.get("path", "")
            return f"HTTP {method} {host}{path} ({size} bytes)"

        # TLS message
        if tls_info:
            sni = tls_info.get("sni", "")
            version = tls_info.get("version", "")
            if sni:
                return f"TLS {version} {src_ip} -> {sni} ({size} bytes)"
            return f"TLS {version} {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({size} bytes)"

        # Generic TCP/UDP
        src = f"{src_ip}:{src_port}" if src_port is not None else src_ip
        dst = f"{dst_ip}:{dst_port}" if dst_port is not None else dst_ip
        flags_part = f" [{flags}]" if flags else ""
        return f"{proto} {src} \u2192 {dst}{flags_part} ({size} bytes)"

    # ------------------------------------------------------------------
    # Protocol-specific parsers
    # ------------------------------------------------------------------

    def _try_parse_dns(self, payload: bytes) -> dict[str, Any] | None:
        """Attempt to parse payload as a DNS message (UDP)."""
        if not payload or len(payload) < 12:
            return None
        try:
            dns = dpkt.dns.DNS(payload)
            return self._extract_dns(dns)
        except (dpkt.UnpackError, Exception):
            return None

    def _try_parse_dns_tcp(self, payload: bytes) -> dict[str, Any] | None:
        """Attempt to parse DNS over TCP (2-byte length prefix)."""
        if not payload or len(payload) < 14:
            return None
        try:
            # TCP DNS has a 2-byte length prefix
            msg_len = struct.unpack("!H", payload[:2])[0]
            if msg_len + 2 > len(payload):
                return None
            dns = dpkt.dns.DNS(payload[2 : 2 + msg_len])
            return self._extract_dns(dns)
        except (dpkt.UnpackError, struct.error, Exception):
            return None

    def _extract_dns(self, dns: Any) -> dict[str, Any] | None:
        """Extract query name, type, and response answers from a parsed DNS object."""
        result: dict[str, Any] = {}

        # Query info
        if dns.qd:
            q = dns.qd[0]
            result["query_name"] = q.name
            qtype_map = {
                dpkt.dns.DNS_A: "A",
                dpkt.dns.DNS_AAAA: "AAAA",
                dpkt.dns.DNS_CNAME: "CNAME",
                dpkt.dns.DNS_MX: "MX",
                dpkt.dns.DNS_NS: "NS",
                dpkt.dns.DNS_PTR: "PTR",
                dpkt.dns.DNS_SOA: "SOA",
                dpkt.dns.DNS_SRV: "SRV",
                dpkt.dns.DNS_TXT: "TXT",
            }
            result["query_type"] = qtype_map.get(q.type, f"TYPE-{q.type}")

        # Answers
        answers = []
        for rr in dns.an:
            if rr.type == dpkt.dns.DNS_A:
                try:
                    answers.append(socket.inet_ntop(socket.AF_INET, rr.rdata))
                except (ValueError, OSError):
                    answers.append(rr.rdata.hex())
            elif rr.type == dpkt.dns.DNS_AAAA:
                try:
                    answers.append(socket.inet_ntop(socket.AF_INET6, rr.rdata))
                except (ValueError, OSError):
                    answers.append(rr.rdata.hex())
            elif rr.type == dpkt.dns.DNS_CNAME:
                answers.append(rr.cname)
            elif rr.type == dpkt.dns.DNS_MX:
                answers.append(rr.mxname)
            elif rr.type == dpkt.dns.DNS_PTR:
                answers.append(rr.ptrname)
            elif rr.type == dpkt.dns.DNS_TXT:
                # TXT records can be multi-part
                if isinstance(rr.rdata, (list, tuple)):
                    answers.append(" ".join(str(t) for t in rr.rdata))
                else:
                    answers.append(str(rr.rdata))
            elif hasattr(rr, "rdata"):
                answers.append(rr.rdata.hex() if isinstance(rr.rdata, bytes) else str(rr.rdata))

        if answers:
            result["answers"] = answers

        # Response code
        rcode_map = {
            dpkt.dns.DNS_RCODE_NOERR: "NOERROR",
            dpkt.dns.DNS_RCODE_FORMERR: "FORMERR",
            dpkt.dns.DNS_RCODE_SERVFAIL: "SERVFAIL",
            dpkt.dns.DNS_RCODE_NXDOMAIN: "NXDOMAIN",
            dpkt.dns.DNS_RCODE_NOTIMP: "NOTIMP",
            dpkt.dns.DNS_RCODE_REFUSED: "REFUSED",
        }
        result["rcode"] = rcode_map.get(dns.rcode, f"RCODE-{dns.rcode}")
        result["is_response"] = bool(dns.qr)

        return result if result.get("query_name") else None

    def _try_parse_http(self, payload: bytes) -> dict[str, Any] | None:
        """Attempt to parse payload as an HTTP request."""
        if not payload or len(payload) < 16:
            return None

        # Quick check: does it start with a known HTTP method?
        http_methods = (
            b"GET ",
            b"POST ",
            b"PUT ",
            b"DELETE ",
            b"HEAD ",
            b"OPTIONS ",
            b"PATCH ",
            b"CONNECT ",
            b"TRACE ",
        )
        starts_with_method = any(payload.startswith(m) for m in http_methods)
        if not starts_with_method:
            return None

        try:
            req = dpkt.http.Request(payload)
            result: dict[str, Any] = {
                "method": req.method,
                "path": req.uri,
                "version": req.version,
            }
            if "host" in req.headers:
                result["host"] = req.headers["host"]
            if "user-agent" in req.headers:
                result["user_agent"] = req.headers["user-agent"]
            if "content-type" in req.headers:
                result["content_type"] = req.headers["content-type"]
            if "content-length" in req.headers:
                result["content_length"] = req.headers["content-length"]
            return result
        except (dpkt.UnpackError, Exception):
            return None

    def _try_parse_tls(self, payload: bytes) -> dict[str, Any] | None:
        """Attempt to parse TLS ClientHello to extract SNI and version."""
        if not payload or len(payload) < 6:
            return None

        # TLS record: content_type=22 (handshake), version >= 0x0301
        if payload[0] != 0x16:
            return None

        try:
            tls_records = dpkt.ssl.TLSMultiFactory(payload)
        except (dpkt.UnpackError, dpkt.ssl.SSL3Exception, Exception):
            return None

        for record, _length in tls_records:
            if not isinstance(record, dpkt.ssl.TLSRecord):
                continue

            # We only care about Handshake records (type 22)
            if record.type != 22:
                continue

            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except (dpkt.UnpackError, Exception):
                continue

            # Only extract from ClientHello (type 1)
            if handshake.type != 1:
                continue

            # Map TLS version
            version_map = {
                (3, 1): "TLS 1.0",
                (3, 2): "TLS 1.1",
                (3, 3): "TLS 1.2",
                (3, 4): "TLS 1.3",
            }

            ch = handshake.data
            tls_version = ""
            if hasattr(ch, "version"):
                major = (ch.version >> 8) & 0xFF
                minor = ch.version & 0xFF
                tls_version = version_map.get((major, minor), f"TLS {major}.{minor}")

            # Extract SNI from extensions
            sni = self._extract_sni_from_client_hello(record.data)

            result: dict[str, Any] = {}
            if tls_version:
                result["version"] = tls_version
            if sni:
                result["sni"] = sni
            result["handshake_type"] = "ClientHello"
            return result if result else None

        return None

    def _extract_sni_from_client_hello(self, handshake_data: bytes) -> str:
        """Extract SNI from raw TLS ClientHello handshake data."""
        # SNI extension type = 0x0000 (server_name)
        # We search for the extension in raw bytes since dpkt's ClientHello
        # parsing of extensions can be incomplete.
        try:
            # Find SNI extension (type 0x0000) in the handshake data
            # Extension format: type(2) + length(2) + SNI list length(2) +
            #   name_type(1) + name_length(2) + name(variable)
            idx = 0
            data = handshake_data

            # Skip past handshake header (type=1 byte, length=3 bytes)
            if len(data) < 4:
                return ""
            idx = 4

            # Skip client version (2 bytes) + random (32 bytes)
            idx += 34
            if idx >= len(data):
                return ""

            # Skip session ID
            if idx < len(data):
                sess_id_len = data[idx]
                idx += 1 + sess_id_len

            # Skip cipher suites
            if idx + 2 <= len(data):
                cs_len = struct.unpack("!H", data[idx : idx + 2])[0]
                idx += 2 + cs_len

            # Skip compression methods
            if idx < len(data):
                comp_len = data[idx]
                idx += 1 + comp_len

            # Extensions length
            if idx + 2 > len(data):
                return ""
            ext_len = struct.unpack("!H", data[idx : idx + 2])[0]
            idx += 2

            ext_end = idx + ext_len
            while idx + 4 <= ext_end and idx + 4 <= len(data):
                ext_type = struct.unpack("!H", data[idx : idx + 2])[0]
                ext_data_len = struct.unpack("!H", data[idx + 2 : idx + 4])[0]
                idx += 4

                if ext_type == 0x0000:  # SNI extension
                    # SNI list: list_length(2) + name_type(1) + name_length(2) + name
                    if idx + 5 <= len(data):
                        _list_len = struct.unpack("!H", data[idx : idx + 2])[0]
                        name_type = data[idx + 2]
                        name_len = struct.unpack("!H", data[idx + 3 : idx + 5])[0]
                        if name_type == 0 and idx + 5 + name_len <= len(data):
                            return data[idx + 5 : idx + 5 + name_len].decode(
                                "ascii", errors="replace"
                            )
                    return ""

                idx += ext_data_len

        except (struct.error, IndexError, Exception):
            pass
        return ""

    def get_stats(self) -> dict[str, Any]:
        stats: dict[str, Any] = {
            "packets_total": self._packets_total,
            "packets_parsed": self._packets_parsed,
            "packets_skipped": self._packets_skipped,
        }

        if self._sample_rate > 1:
            stats["sampling_rate"] = self._sample_rate
            stats["packets_sampled_out"] = self._packets_sampled
            stats["sampling_note"] = (
                f"Capture exceeded {MAX_PACKETS_BEFORE_SAMPLING:,} packets. "
                f"Sampled every {self._sample_rate} packets "
                f"({self._packets_parsed:,} of {self._packets_total:,} processed)."
            )

        # Protocol distribution
        if self._protocol_counts:
            stats["protocol_distribution"] = dict(
                sorted(self._protocol_counts.items(), key=lambda x: x[1], reverse=True)
            )

        # Top connections
        if self._connection_pairs:
            top_connections = sorted(
                self._connection_pairs.items(), key=lambda x: x[1], reverse=True
            )[:20]
            stats["top_connections"] = [
                {"connection": k, "packet_count": v} for k, v in top_connections
            ]

        # Protocol-specific stats
        stats["dns_queries"] = self._dns_queries
        stats["http_requests"] = self._http_requests
        stats["tls_handshakes"] = self._tls_handshakes

        return stats
