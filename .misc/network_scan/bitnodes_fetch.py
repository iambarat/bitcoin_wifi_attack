#!/usr/bin/env python3
"""bitnodes_fetch.py

Fetch reachable Bitcoin nodes from the Bitnodes API (v1).

Outputs:
- CSV: one address per row (no header)
- JSON: metadata + full nodes dict

Examples:
  python bitnodes_fetch.py --mode latest --csv
  python bitnodes_fetch.py --mode pinned --json --out nodes.json
  python bitnodes_fetch.py --csv --json --out ./out/nodes
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE_URL = "https://bitnodes.io/api/v1"
LATEST_URL = f"{BASE_URL}/snapshots/latest/"
LIST_URL = f"{BASE_URL}/snapshots/?limit=1"

DEFAULT_TIMEOUT = 20
MAX_RETRIES = 5
BACKOFF_BASE = 1.2
BACKOFF_CAP = 30


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Parse Retry-After header to seconds (if possible)."""
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    # Numeric seconds
    if value.isdigit():
        return float(value)
    # HTTP-date
    try:
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delay = (dt - now).total_seconds()
        return max(0.0, delay)
    except Exception:
        return None


def _sleep_with_cap(seconds: float) -> None:
    """Sleep helper that caps long sleeps to avoid hanging too long."""
    time.sleep(min(seconds, BACKOFF_CAP))


def _request_json(url: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """HTTP GET JSON with retries, respecting Retry-After for HTTP 429."""
    headers = {
        "User-Agent": "bitnodes-fetch/1.0 (+https://bitnodes.io/)"
    }

    attempt = 0
    while True:
        attempt += 1
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=timeout) as resp:
                # Assume UTF-8 JSON
                data = resp.read().decode("utf-8")
                return json.loads(data)
        except HTTPError as e:
            # Handle rate limiting
            if e.code == 429:
                retry_after = _parse_retry_after(e.headers.get("Retry-After"))
                if retry_after is None:
                    retry_after = BACKOFF_BASE ** attempt
                logging.warning("HTTP 429 received; retrying in %.1fs", retry_after)
                _sleep_with_cap(retry_after)
            elif 500 <= e.code < 600:
                # Transient server errors
                if attempt >= MAX_RETRIES:
                    raise
                delay = min(BACKOFF_BASE ** attempt, BACKOFF_CAP)
                logging.warning("HTTP %s; retrying in %.1fs", e.code, delay)
                _sleep_with_cap(delay)
            else:
                raise
        except URLError as e:
            if attempt >= MAX_RETRIES:
                raise
            delay = min(BACKOFF_BASE ** attempt, BACKOFF_CAP)
            logging.warning("Network error (%s); retrying in %.1fs", e.reason, delay)
            _sleep_with_cap(delay)
        except Exception:
            if attempt >= MAX_RETRIES:
                raise
            delay = min(BACKOFF_BASE ** attempt, BACKOFF_CAP)
            logging.warning("Unexpected error; retrying in %.1fs", delay)
            _sleep_with_cap(delay)


def _extract_timestamp_from_list(payload: Dict[str, Any]) -> int:
    """Extract snapshot timestamp from the list endpoint payload.

    The list endpoint may contain results with timestamp and/or url fields.
    """
    results = payload.get("results")
    if isinstance(results, list) and results:
        first = results[0]
        if isinstance(first, dict):
            if "timestamp" in first:
                return int(first["timestamp"])
            url = first.get("url")
            if isinstance(url, str) and "/snapshots/" in url:
                # URL ends with /snapshots/<timestamp>/
                try:
                    ts_str = url.rstrip("/").split("/")[-1]
                    return int(ts_str)
                except Exception:
                    pass
    # Fallback: some formats may include "snapshots": [..]
    snapshots = payload.get("snapshots")
    if isinstance(snapshots, list) and snapshots:
        first = snapshots[0]
        if isinstance(first, dict) and "timestamp" in first:
            return int(first["timestamp"])
    raise ValueError("Unable to determine snapshot timestamp from list payload")


def fetch_nodes(mode: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Fetch snapshot payload and derived metadata.

    Returns:
        payload: raw snapshot JSON
        meta: dict of metadata
    """
    if mode == "latest":
        payload = _request_json(LATEST_URL)
    elif mode == "pinned":
        listing = _request_json(LIST_URL)
        ts = _extract_timestamp_from_list(listing)
        payload = _request_json(f"{BASE_URL}/snapshots/{ts}/")
    else:
        raise ValueError(f"Unknown mode: {mode}")

    meta = {
        "mode": mode,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "timestamp": payload.get("timestamp"),
        "total_nodes": payload.get("total_nodes"),
        "latest_height": payload.get("latest_height"),
    }
    return payload, meta


def _write_json(obj: Dict[str, Any], out_path: Optional[str]) -> None:
    """Write JSON to a file or stdout."""
    text = json.dumps(obj, indent=2, sort_keys=True)
    if out_path is None or out_path == "-":
        sys.stdout.write(text + "\n")
        return

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text + "\n")


def _write_csv_lines(lines: Iterable[str], out_path: Optional[str]) -> None:
    """Write lines as a single-column CSV without a header."""
    if out_path is None or out_path == "-":
        writer = csv.writer(sys.stdout)
        for line in lines:
            writer.writerow([line])
        return

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        for line in lines:
            writer.writerow([line])


def _resolve_outputs(
    out: str, want_json: bool, want_csv: bool
) -> Tuple[Optional[str], Optional[str]]:
    """Resolve output paths for JSON and CSV based on --out and flags."""
    if not want_json and not want_csv:
        want_csv = True

    # Single format: allow stdout
    if want_json and not want_csv:
        return (None, out)
    if want_csv and not want_json:
        return (out, None)

    # Both formats
    if out == "-":
        raise ValueError("--out must be a file path or directory when using multiple formats")

    # If --out is a directory or ends with path separator, use default names.
    if out.endswith(os.sep) or (os.path.exists(out) and os.path.isdir(out)):
        out_dir = out
        os.makedirs(out_dir, exist_ok=True)
        json_path = os.path.join(out_dir, "nodes.json") if want_json else None
        csv_path = os.path.join(out_dir, "nodes.csv") if want_csv else None
        return (csv_path, json_path)

    # Treat --out as a base path (strip extension if present)
    base, ext = os.path.splitext(out)
    if ext.lower() in {".json", ".csv"}:
        out = base
    json_path = out + ".json" if want_json else None
    csv_path = out + ".csv" if want_csv else None
    return (csv_path, json_path)


def build_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    p = argparse.ArgumentParser(description="Fetch reachable Bitcoin nodes from Bitnodes.")
    p.add_argument(
        "--mode",
        choices=["latest", "pinned"],
        default="latest",
        help="Fetch latest snapshot or pinned snapshot (reproducible).",
    )
    p.add_argument(
        "--out",
        default="nodes.csv",
        help="Output path or '-' for stdout. If multiple formats, use a base path or directory.",
    )
    p.add_argument("--csv", action="store_true", help="Output as CSV (one address per row).")
    p.add_argument("--json", action="store_true", help="Output as JSON (meta + full nodes dict).")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    """CLI entry point."""
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    want_json = bool(args.json)
    want_csv = bool(args.csv)
    if not want_json and not want_csv:
        want_csv = True

    try:
        csv_out, json_out = _resolve_outputs(args.out, want_json, want_csv)
    except ValueError as e:
        logging.error(str(e))
        return 2

    try:
        payload, meta = fetch_nodes(args.mode)
    except Exception as e:
        logging.error("Failed to fetch nodes: %s", e)
        return 1

    nodes = payload.get("nodes")
    if not isinstance(nodes, dict):
        logging.error("Unexpected payload format: 'nodes' is missing or not a dict")
        return 1

    # Output CSV
    if want_csv:
        _write_csv_lines(nodes.keys(), csv_out)

    # Output JSON
    if want_json:
        out_obj = {
            "meta": meta,
            "nodes": nodes,
        }
        _write_json(out_obj, json_out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
