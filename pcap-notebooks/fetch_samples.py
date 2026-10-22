"""Download the public sample captures listed in samples.json and verify their sha256.

Usage: python fetch_samples.py          # fetch every sample into ./data
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "samples.json"
DATA_DIR = HERE / "data"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ensure(name: str, data_dir: Path = DATA_DIR, manifest: Path = MANIFEST) -> Path:
    """Return the local path of a verified sample, downloading it if needed."""
    entry = json.loads(manifest.read_text(encoding="utf-8"))["samples"][name]
    if not entry["url"].startswith("https://"):
        raise ValueError(f"{name}: only https URLs are allowed")
    target = data_dir / name
    if target.exists() and sha256(target) == entry["sha256"]:
        return target
    data_dir.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    with urllib.request.urlopen(entry["url"], timeout=60) as resp:
        partial.write_bytes(resp.read())
    actual = sha256(partial)
    if actual != entry["sha256"]:
        partial.unlink()
        raise ValueError(f"{name}: sha256 mismatch (expected {entry['sha256']}, got {actual})")
    partial.replace(target)
    return target


def main() -> int:
    for name in json.loads(MANIFEST.read_text(encoding="utf-8"))["samples"]:
        print(f"{ensure(name)}  ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
