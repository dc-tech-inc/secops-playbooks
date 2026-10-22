# PCAP notebooks: network forensics on public captures

Three Jupyter notebooks that triage public sample captures from the [Wireshark wiki](https://wiki.wireshark.org/SampleCaptures). No capture from DCtech. or any client is used, and the samples are not redistributed here: [`fetch_samples.py`](fetch_samples.py) downloads them on demand into `data/` (git-ignored) and refuses any file whose sha256 differs from [`samples.json`](samples.json).

| Notebook | Capture | Question |
|---|---|---|
| [`01-dns-triage`](notebooks/01-dns-triage.ipynb) | `dns.cap` | Which lookups fail, which go unanswered, what record types appear? |
| [`02-http-review`](notebooks/02-http-review.ipynb) | `http_gzip.cap` | Who requested what, with which user agent, and how many bytes moved each way? |
| [`03-arp-storm`](notebooks/03-arp-storm.ipynb) | `arp-storm.pcap` | Which host is flooding ARP, and how hard? |

The parsing lives in [`pcaplib.py`](pcaplib.py) (read-only helpers on top of [dpkt](https://kbandla.github.io/dpkt/)), so the notebooks stay short and the logic is unit-tested.

```bash
pip install -r requirements-ci.txt
python pcap-notebooks/fetch_samples.py                     # download + verify the samples
pytest pcap-notebooks/tests                                # unit tests on a synthetic capture (offline)
pytest --nbmake pcap-notebooks/notebooks                   # execute every notebook end to end
```

Each notebook ends its cells with `assert`s on the findings (for example "exactly one MAC peaks at 34 ARP requests/s"), so CI fails if the analysis or the data changes. Notebooks are committed without outputs; CI runs them with [nbmake](https://github.com/treebeardtech/nbmake).

## Limitations

- Classic libpcap, Ethernet link type only. pcapng and other link types are rejected with a clear error.
- HTTP parsing looks at requests that start at the beginning of a TCP segment; there is no TCP stream reassembly. TLS content is out of scope.
- The ARP threshold (20 requests/s per sender) is a starting point for a small VLAN, not a universal value.
- The samples are protocol demonstrations, not incident data, so the "findings" are deliberately mundane.
