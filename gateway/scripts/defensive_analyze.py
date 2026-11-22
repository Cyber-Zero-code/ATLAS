#!/usr/bin/env python3
"""
Project ATLAS — Isolated Python 3 Defensive Analysis Utility
Executed ONLY via fixed path and isolated Python flags (`python3 -I -S -E`).
Reads a staged dataset inside the org sandbox and emits structured JSON summary.
"""

import csv
import ipaddress
import json
import os
import re
import sys
from collections import Counter

MAX_READ_BYTES = 2 * 1024 * 1024
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,12}\b")


def load_bounded_text(path: str) -> str:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Staged dataset not found: {os.path.basename(path)}")
    size = os.path.getsize(path)
    if size > MAX_READ_BYTES:
        raise ValueError(f"Dataset exceeds 2 MB defensive analysis cap ({size} bytes)")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def run_ioc_stats(text: str) -> dict:
    ips = [ip for ip in IP_RE.findall(text)]
    valid_ips = []
    private_ips = 0
    public_ips = 0
    for ip in ips:
        try:
            obj = ipaddress.ip_address(ip)
            valid_ips.append(ip)
            if obj.is_private:
                private_ips += 1
            else:
                public_ips += 1
        except ValueError:
            continue
    domains = [d.lower() for d in DOMAIN_RE.findall(text)]
    return {
        "preset": "ioc_stats",
        "total_ip_mentions": len(valid_ips),
        "unique_ips": len(set(valid_ips)),
        "private_ip_mentions": private_ips,
        "public_ip_mentions": public_ips,
        "top_ips": Counter(valid_ips).most_common(10),
        "unique_domains": len(set(domains)),
        "top_domains": Counter(domains).most_common(10),
    }


def run_log_summary(text: str) -> dict:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    severity_hits = Counter()
    for ln in lines:
        low = ln.lower()
        for kw in ("critical", "error", "warn", "denied", "failed", "blocked", "timeout"):
            if kw in low:
                severity_hits[kw] += 1
    return {
        "preset": "log_summary",
        "line_count": len(lines),
        "keyword_counts": dict(severity_hits),
        "ioc_stats": run_ioc_stats(text),
    }


def run_csv_correlate(text: str) -> dict:
    reader = csv.DictReader(text.splitlines())
    rows = list(reader)
    return {
        "preset": "csv_correlate",
        "columns": reader.fieldnames or [],
        "row_count": len(rows),
        "ioc_stats": run_ioc_stats(text),
    }


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write("Usage: defensive_analyze.py <ioc_stats|log_summary|csv_correlate> <dataset_path>\n")
        return 2
    preset, dataset_path = sys.argv[1], sys.argv[2]
    text = load_bounded_text(dataset_path)
    if preset == "ioc_stats":
        out = run_ioc_stats(text)
    elif preset == "log_summary":
        out = run_log_summary(text)
    elif preset == "csv_correlate":
        out = run_csv_correlate(text)
    else:
        sys.stderr.write(f"Unsupported preset: {preset}\n")
        return 2
    sys.stdout.write(json.dumps(out, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
