#!/usr/bin/env python3
"""Concurrent DNS discovery over MCC/MNC combinations and an FQDN template.

Use only in environments where you have explicit authorization to resolve and
record the resulting hostnames. This script performs DNS lookups only (no port scan).

Example:
  python scripts/batch_fqdn_discovery.py \\
    --template "epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org" \\
    --mcc-min 460 --mcc-max 460 --mnc-min 0 --mnc-max 20 --max-combos 10
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import socket
import sys
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path


def _pad_mnc_for_fqdn(mnc_digits: int) -> str:
    """Format numeric MNC for typical 3GPP FQDN segments (three digits, zero-padded)."""
    return f"{mnc_digits:03d}"


def _normalize_mcc_str(mcc_val: int) -> str:
    return f"{mcc_val:03d}"


def iter_mcc_mnc_combos(
    mcc_min: int,
    mcc_max: int,
    mnc_min: int,
    mnc_max: int,
    *,
    max_combos: int | None,
) -> Iterator[tuple[str, str]]:
    """Yield (mcc_str, mnc_str) covering MCC as 3-digit and MNC as 2–3 digit practice via 000–999 padding."""
    n = 0
    for mcc in range(mcc_min, mcc_max + 1):
        mcc_s = _normalize_mcc_str(mcc)
        for mnc in range(mnc_min, mnc_max + 1):
            mnc_s = _pad_mnc_for_fqdn(mnc)
            yield mcc_s, mnc_s
            n += 1
            if max_combos is not None and n >= max_combos:
                return


def render_fqdn(template: str, mcc: str, mnc: str) -> str:
    out = template
    out = re.sub(r"\{mcc\}", mcc, out, flags=re.IGNORECASE)
    out = re.sub(r"\{mnc\}", mnc, out, flags=re.IGNORECASE)
    out = re.sub(r"<MCC>", mcc, out, flags=re.IGNORECASE)
    out = re.sub(r"<MNC>", mnc, out, flags=re.IGNORECASE)
    return out


def is_public_resolved_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    return True


def resolve_fqdn_sync(fqdn: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(fqdn, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    ips: list[str] = []
    for item in infos:
        sockaddr = item[4]
        if sockaddr and sockaddr[0]:
            ips.append(sockaddr[0])
    return list(dict.fromkeys(ips))


async def main_async(args: argparse.Namespace) -> int:
    out_path = Path(args.output).resolve()
    template: str = args.template
    concurrency = max(1, args.concurrency)

    combos = list(
        iter_mcc_mnc_combos(
            args.mcc_min,
            args.mcc_max,
            args.mnc_min,
            args.mnc_max,
            max_combos=args.max_combos,
        )
    )
    total = len(combos)
    if total == 0:
        print("No MCC/MNC combinations to scan (check ranges and --max-combos).", file=sys.stderr)
        return 1

    found: list[dict] = []
    lock = asyncio.Lock()
    done = 0
    hits = 0
    sem = asyncio.Semaphore(concurrency)

    def flush_found() -> None:
        out_path.write_text(json.dumps(found, ensure_ascii=False, indent=2), encoding="utf-8")

    async def one(mcc_s: str, mnc_s: str) -> None:
        nonlocal done, hits
        fqdn = render_fqdn(template, mcc_s, mnc_s)
        async with sem:
            ips = await asyncio.to_thread(resolve_fqdn_sync, fqdn)
        public_ips = [ip for ip in ips if is_public_resolved_ip(ip)]
        async with lock:
            done += 1
            if public_ips:
                hits += 1
                rec = {
                    "fqdn": fqdn,
                    "mcc": mcc_s,
                    "mnc": mnc_s,
                    "ips": public_ips,
                    "resolved_at": datetime.now(timezone.utc).isoformat(),
                }
                found.append(rec)
                print(f"[HIT] {fqdn} -> {', '.join(public_ips)}", flush=True)
                try:
                    flush_found()
                except OSError as exc:
                    print(f"[WARN] could not write {out_path}: {exc}", file=sys.stderr)
            if done % max(1, total // 20) == 0 or done == total:
                print(f"[PROGRESS] {done}/{total} resolved, public hits: {hits}", flush=True)

    await asyncio.gather(*[one(mcc_s, mnc_s) for mcc_s, mnc_s in combos])
    try:
        flush_found()
    except OSError as exc:
        print(f"[WARN] final write failed: {exc}", file=sys.stderr)
    print(f"Done. total={total}, public_hits={hits}, output={out_path}")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Batch DNS discovery for 3GPP-style FQDN templates.")
    p.add_argument(
        "--template",
        required=True,
        help='FQDN template with placeholders, e.g. epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org',
    )
    p.add_argument("--concurrency", type=int, default=50, help="Max concurrent DNS lookups (default: 50)")
    p.add_argument(
        "--output",
        default="found_targets.json",
        help="JSON file for hits (default: found_targets.json in CWD)",
    )
    p.add_argument("--mcc-min", type=int, default=1, help="Inclusive MCC lower bound (default: 1)")
    p.add_argument("--mcc-max", type=int, default=999, help="Inclusive MCC upper bound (default: 999)")
    p.add_argument("--mnc-min", type=int, default=0, help="Inclusive MNC lower bound (default: 0)")
    p.add_argument("--mnc-max", type=int, default=999, help="Inclusive MNC upper bound (default: 999)")
    p.add_argument(
        "--max-combos",
        type=int,
        default=None,
        help="Stop after this many (mcc,mnc) pairs (default: no limit)",
    )
    return p


def main() -> int:
    args = build_arg_parser().parse_args()
    if args.mcc_min > args.mcc_max or args.mnc_min > args.mnc_max:
        print("Invalid range: min must be <= max for MCC and MNC.", file=sys.stderr)
        return 1
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
