"""Small, read-only helpers for triaging classic libpcap captures with dpkt.

Everything here parses packets that are already on disk. Nothing sends traffic.
"""

from __future__ import annotations

import socket
from collections import Counter, defaultdict
from collections.abc import Iterator
from pathlib import Path

import dpkt

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 29: "LOC", 33: "SRV", 255: "ANY"}


def _ip(raw: bytes) -> str:
    family = socket.AF_INET6 if len(raw) == 16 else socket.AF_INET
    return socket.inet_ntop(family, raw)


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def frames(path: Path | str) -> Iterator[tuple[float, dpkt.ethernet.Ethernet]]:
    """Yield (timestamp, ethernet frame) for an Ethernet-linktype pcap file."""
    with open(path, "rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        if reader.datalink() != dpkt.pcap.DLT_EN10MB:
            raise ValueError(f"{path}: only Ethernet captures are supported (linktype {reader.datalink()})")
        for ts, buf in reader:
            yield ts, dpkt.ethernet.Ethernet(buf)


def protocol_counts(path: Path | str) -> Counter[str]:
    """Count frames by network/transport layer, e.g. 'IPv4/UDP', 'ARP'."""
    counts: Counter[str] = Counter()
    for _, eth in frames(path):
        net = eth.data
        if isinstance(net, dpkt.arp.ARP):
            counts["ARP"] += 1
        elif isinstance(net, dpkt.ip.IP | dpkt.ip6.IP6):
            family = "IPv4" if isinstance(net, dpkt.ip.IP) else "IPv6"
            counts[f"{family}/{type(net.data).__name__}"] += 1
        else:
            counts["other"] += 1
    return counts


def conversations(path: Path | str) -> Counter[tuple[str, str]]:
    """Bytes sent per (src, dst) IP pair."""
    talk: Counter[tuple[str, str]] = Counter()
    for _, eth in frames(path):
        if isinstance(eth.data, dpkt.ip.IP):
            talk[(_ip(eth.data.src), _ip(eth.data.dst))] += eth.data.len
    return talk


def dns_messages(path: Path | str) -> list[dict]:
    """Parse DNS over UDP/53 into dicts with query names, types and answers."""
    out = []
    for ts, eth in frames(path):
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.udp.UDP):
            continue
        udp = ip.data
        if 53 not in (udp.sport, udp.dport):
            continue
        try:
            dns = dpkt.dns.DNS(udp.data)
        except (dpkt.UnpackError, IndexError):
            continue
        answers = []
        for rr in dns.an:
            if rr.type in (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA):
                answers.append(_ip(rr.rdata))
            elif rr.type in (dpkt.dns.DNS_CNAME, dpkt.dns.DNS_PTR, dpkt.dns.DNS_NS):
                answers.append(getattr(rr, "cname", None) or getattr(rr, "ptrname", None) or getattr(rr, "nsname", ""))
        out.append(
            {
                "ts": ts,
                "src": _ip(ip.src),
                "dst": _ip(ip.dst),
                "id": dns.id,
                "response": bool(dns.qr),
                "rcode": dns.rcode,
                "qname": dns.qd[0].name if dns.qd else "",
                "qtype": DNS_TYPES.get(dns.qd[0].type, str(dns.qd[0].type)) if dns.qd else "",
                "answers": answers,
            }
        )
    return out


def unanswered_dns(messages: list[dict]) -> list[dict]:
    """Queries with no response carrying the same id and name (lost or blocked lookups)."""
    answered = {(m["id"], m["qname"]) for m in messages if m["response"]}
    return [m for m in messages if not m["response"] and (m["id"], m["qname"]) not in answered]


def nxdomain_names(messages: list[dict]) -> list[str]:
    """Names answered with NXDOMAIN (rcode 3), in first-seen order. Bursts hint at DGA or typos."""
    seen: dict[str, None] = {}
    for m in messages:
        if m["response"] and m["rcode"] == dpkt.dns.DNS_RCODE_NXDOMAIN:
            seen.setdefault(m["qname"], None)
    return list(seen)


def http_requests(path: Path | str) -> list[dict]:
    """Extract HTTP/1.x requests that start at the beginning of a TCP segment."""
    out = []
    for ts, eth in frames(path):
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP) or not ip.data.data:
            continue
        try:
            req = dpkt.http.Request(ip.data.data)
        except (dpkt.UnpackError, dpkt.NeedData):
            continue
        out.append(
            {
                "ts": ts,
                "src": _ip(ip.src),
                "dst": _ip(ip.dst),
                "dport": ip.data.dport,
                "method": req.method,
                "host": req.headers.get("host", ""),
                "uri": req.uri,
                "user_agent": req.headers.get("user-agent", ""),
            }
        )
    return out


def arp_request_rates(path: Path | str, window: float = 1.0) -> dict[str, int]:
    """Peak number of ARP requests each sender MAC issued inside any `window`-second bucket."""
    buckets: dict[str, Counter[int]] = defaultdict(Counter)
    for ts, eth in frames(path):
        arp = eth.data
        if isinstance(arp, dpkt.arp.ARP) and arp.op == dpkt.arp.ARP_OP_REQUEST:
            buckets[_mac(arp.sha)][int(ts // window)] += 1
    return {mac: max(c.values()) for mac, c in buckets.items()}


def arp_storm_suspects(path: Path | str, threshold: int = 20, window: float = 1.0) -> list[tuple[str, int]]:
    """Senders whose peak ARP request rate meets `threshold` per `window`, highest first."""
    rates = arp_request_rates(path, window)
    return sorted(((m, r) for m, r in rates.items() if r >= threshold), key=lambda x: -x[1])
