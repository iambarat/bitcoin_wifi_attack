#!/usr/bin/env python3
"""filter_ipv4_only.py

Filter a CSV list of node addresses to only IPv4 entries (host:port).
Skips .onion and IPv6 (including bracketed IPv6).

Examples:
  python filter_ipv4_only.py --input nodes.csv --out ipv4_nodes.csv
  python filter_ipv4_only.py -i nodes.csv -o -
  python filter_ipv4_only.py --column address --out ipv4_nodes.csv
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import os
import sys
from typing import Iterable, List, Optional, Tuple


def _detect_dialect(sample: str) -> csv.Dialect:
    try:
        return csv.Sniffer().sniff(sample)
    except Exception:
        return csv.excel


def _parse_column_spec(column: Optional[str]) -> Optional[Tuple[str, int]]:
    if column is None:
        return None
    column = column.strip()
    if not column:
        return None
    if column.isdigit():
        return ("index", int(column))
    return ("name", column.lower())


def _is_header_row(row: List[str]) -> bool:
    if not row:
        return False
    joined = ",".join(row).strip().lower()
    for token in ("address", "addr", "node", "host", "endpoint"):
        if token in joined:
            return True
    return False


def _pick_column_index(header: List[str]) -> Optional[int]:
    header_lc = [h.strip().lower() for h in header]
    for token in ("address", "addr", "node", "host", "endpoint"):
        if token in header_lc:
            return header_lc.index(token)
    return None


def read_addresses(path: str, column: Optional[str]) -> List[str]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        sample = f.read(2048)
        f.seek(0)
        dialect = _detect_dialect(sample)
        reader = csv.reader(f, dialect)

        try:
            first = next(reader)
        except StopIteration:
            return []

        column_spec = _parse_column_spec(column)
        header_row = False
        col_idx: Optional[int] = None

        if column_spec is None:
            if _is_header_row(first):
                header_row = True
                col_idx = _pick_column_index(first)
            else:
                col_idx = 0
        elif column_spec[0] == "index":
            col_idx = column_spec[1]
        else:
            header_row = True
            col_idx = _pick_column_index(first)
            if col_idx is None:
                col_idx = 0

        addresses: List[str] = []

        def add_from_row(row: List[str]) -> None:
            if col_idx is None:
                return
            if col_idx >= len(row):
                return
            value = row[col_idx].strip()
            # If the CSV sniffer chose ":" as a delimiter, rejoin ip:port.
            if col_idx == 0 and len(row) == 2 and row[1].strip().isdigit():
                value = f"{row[0].strip()}:{row[1].strip()}"
            if not value or value.startswith("#"):
                return
            addresses.append(value)

        if not header_row:
            add_from_row(first)

        for row in reader:
            add_from_row(row)

        return addresses


def _is_ipv4_host(host: str) -> bool:
    try:
        ipaddress.IPv4Address(host)
        return True
    except Exception:
        return False


def _split_host_port(addr: str) -> Optional[Tuple[str, int]]:
    if addr.count(":") == 1 and "[" not in addr:
        host, port_str = addr.rsplit(":", 1)
    else:
        return None
    host = host.strip()
    if host.endswith(".onion"):
        return None
    try:
        int(port_str)
    except Exception:
        return None
    if not _is_ipv4_host(host):
        return None
    return host, int(port_str)


def _write_csv_lines(lines: Iterable[str], out_path: str) -> None:
    if out_path == "-" or out_path is None:
        writer = csv.writer(sys.stdout)
        for line in lines:
            writer.writerow([line])
        return

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        for line in lines:
            writer.writerow([line])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Filter input addresses to only IPv4 host:port entries."
    )
    p.add_argument(
        "-i",
        "--input",
        default="nodes.csv",
        help="Input CSV file containing addresses.",
    )
    p.add_argument(
        "-o",
        "--out",
        default="-",
        help="Output CSV path for IPv4 addresses or '-' for stdout.",
    )
    p.add_argument(
        "--column",
        default=None,
        help="Column name or 0-based index (e.g. 'address' or '0').",
    )
    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    addresses = read_addresses(args.input, args.column)

    ipv4_only = []
    for addr in addresses:
        if _split_host_port(addr) is not None:
            ipv4_only.append(addr)

    _write_csv_lines(ipv4_only, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
