"""Unit tests on a synthetic capture written with dpkt, so they need no network access."""

import hashlib
import io
import json
import socket

import dpkt
import pytest

import fetch_samples
import pcaplib

MAC_A = b"\x02\x00\x00\x00\x00\x0a"
MAC_B = b"\x02\x00\x00\x00\x00\x0b"
CLIENT, RESOLVER, WEB = "10.10.20.5", "10.10.30.53", "192.0.2.80"


def _eth(ip_pkt=None, arp=None):
    if arp is not None:
        return dpkt.ethernet.Ethernet(src=MAC_A, dst=b"\xff" * 6, type=dpkt.ethernet.ETH_TYPE_ARP, data=arp)
    return dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP, data=ip_pkt)


def _ip(src, dst, transport, proto):
    pkt = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, data=transport)
    pkt.len = len(bytes(pkt))
    return pkt


def _dns(qid, name, response=False, answer=None):
    msg = dpkt.dns.DNS(id=qid, qd=[dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A)])
    if response:
        msg.qr = dpkt.dns.DNS_R
        msg.an = [dpkt.dns.DNS.RR(name=name, type=dpkt.dns.DNS_A, rdata=socket.inet_aton(answer), ttl=60)]
    return msg


def _udp(sport, dport, payload):
    seg = dpkt.udp.UDP(sport=sport, dport=dport, data=bytes(payload))
    seg.ulen = len(bytes(seg))
    return seg


@pytest.fixture
def capture(tmp_path):
    path = tmp_path / "synthetic.pcap"
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        q = _udp(50000, 53, _dns(1, "intranet.example.com"))
        r = _udp(53, 50000, _dns(1, "intranet.example.com", response=True, answer="10.10.30.10"))
        lost = _udp(50001, 53, _dns(2, "lost.example.com"))
        junk = _udp(50002, 53, b"\x00\x01")
        w.writepkt(bytes(_eth(_ip(CLIENT, RESOLVER, q, dpkt.ip.IP_PROTO_UDP))), ts=100.0)
        w.writepkt(bytes(_eth(_ip(RESOLVER, CLIENT, r, dpkt.ip.IP_PROTO_UDP))), ts=100.1)
        w.writepkt(bytes(_eth(_ip(CLIENT, RESOLVER, lost, dpkt.ip.IP_PROTO_UDP))), ts=100.2)
        w.writepkt(bytes(_eth(_ip(CLIENT, RESOLVER, junk, dpkt.ip.IP_PROTO_UDP))), ts=100.3)
        http = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: drill/1.0\r\n\r\n"
        tcp = dpkt.tcp.TCP(sport=40000, dport=80, flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, data=http)
        w.writepkt(bytes(_eth(_ip(CLIENT, WEB, tcp, dpkt.ip.IP_PROTO_TCP))), ts=101.0)
        ack = dpkt.tcp.TCP(sport=80, dport=40000, flags=dpkt.tcp.TH_ACK)
        w.writepkt(bytes(_eth(_ip(WEB, CLIENT, ack, dpkt.ip.IP_PROTO_TCP))), ts=101.1)
        for i in range(25):
            arp = dpkt.arp.ARP(
                op=dpkt.arp.ARP_OP_REQUEST,
                sha=MAC_A,
                spa=socket.inet_aton(CLIENT),
                tha=b"\x00" * 6,
                tpa=socket.inet_aton(f"10.10.20.{100 + i}"),
            )
            w.writepkt(bytes(_eth(arp=arp)), ts=200.0 + i * 0.01)
        w.writepkt(bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=0x88B5, data=b"x")), ts=300.0)
    return path


def test_protocol_counts(capture):
    assert pcaplib.protocol_counts(capture) == {"IPv4/UDP": 4, "IPv4/TCP": 2, "ARP": 25, "other": 1}


def test_conversations(capture):
    talk = pcaplib.conversations(capture)
    assert (CLIENT, RESOLVER) in talk
    assert talk[(CLIENT, WEB)] > 0


def test_dns_messages_and_unanswered(capture):
    msgs = pcaplib.dns_messages(capture)
    assert len(msgs) == 3  # the 2-byte junk payload is skipped
    response = next(m for m in msgs if m["response"])
    assert response["qname"] == "intranet.example.com"
    assert response["qtype"] == "A"
    assert response["answers"] == ["10.10.30.10"]
    assert [m["qname"] for m in pcaplib.unanswered_dns(msgs)] == ["lost.example.com"]


def test_http_requests(capture):
    reqs = pcaplib.http_requests(capture)
    assert len(reqs) == 1
    assert reqs[0] | {"ts": 0} == {
        "ts": 0,
        "src": CLIENT,
        "dst": WEB,
        "dport": 80,
        "method": "GET",
        "host": "www.example.com",
        "uri": "/index.html",
        "user_agent": "drill/1.0",
    }


def test_arp_storm(capture):
    assert pcaplib.arp_request_rates(capture) == {"02:00:00:00:00:0a": 25}
    assert pcaplib.arp_storm_suspects(capture, threshold=20) == [("02:00:00:00:00:0a", 25)]
    assert pcaplib.arp_storm_suspects(capture, threshold=30) == []


def test_rejects_non_ethernet(tmp_path):
    path = tmp_path / "raw.pcap"
    with open(path, "wb") as fh:
        dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_RAW).writepkt(b"\x45" + b"\x00" * 19, ts=1.0)
    with pytest.raises(ValueError, match="only Ethernet"):
        list(pcaplib.frames(path))


# ---- fetch_samples -----------------------------------------------------------


def _manifest(tmp_path, content: bytes, url="https://example.com/s.pcap", digest=None):
    m = tmp_path / "samples.json"
    entry = {"url": url, "sha256": digest or hashlib.sha256(content).hexdigest()}
    m.write_text(json.dumps({"samples": {"s.pcap": entry}}), encoding="utf-8")
    return m


def test_ensure_downloads_and_verifies(tmp_path, monkeypatch):
    calls = []

    def fake_urlopen(url, timeout):
        calls.append(url)
        return io.BytesIO(b"pcap-bytes")

    monkeypatch.setattr(fetch_samples.urllib.request, "urlopen", fake_urlopen)
    m = _manifest(tmp_path, b"pcap-bytes")
    path = fetch_samples.ensure("s.pcap", data_dir=tmp_path / "data", manifest=m)
    assert path.read_bytes() == b"pcap-bytes"
    fetch_samples.ensure("s.pcap", data_dir=tmp_path / "data", manifest=m)
    assert len(calls) == 1  # cached copy reused once verified


def test_ensure_rejects_hash_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch_samples.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(b"tampered"))
    m = _manifest(tmp_path, b"original")
    with pytest.raises(ValueError, match="sha256 mismatch"):
        fetch_samples.ensure("s.pcap", data_dir=tmp_path / "data", manifest=m)
    assert not (tmp_path / "data" / "s.pcap").exists()


def test_ensure_rejects_non_https(tmp_path):
    m = _manifest(tmp_path, b"x", url="http://example.com/s.pcap")
    with pytest.raises(ValueError, match="https"):
        fetch_samples.ensure("s.pcap", data_dir=tmp_path, manifest=m)


def test_manifest_pins_https_and_sha256():
    manifest = json.loads(fetch_samples.MANIFEST.read_text(encoding="utf-8"))
    for entry in manifest["samples"].values():
        assert entry["url"].startswith("https://wiki.wireshark.org/")
        assert len(entry["sha256"]) == 64


def test_nxdomain_names_dedupes_in_order():
    msgs = [
        {"response": True, "rcode": 3, "qname": "a.example"},
        {"response": False, "rcode": 0, "qname": "b.example"},
        {"response": True, "rcode": 3, "qname": "a.example"},
        {"response": True, "rcode": 0, "qname": "c.example"},
        {"response": True, "rcode": 3, "qname": "d.example"},
    ]
    assert pcaplib.nxdomain_names(msgs) == ["a.example", "d.example"]
