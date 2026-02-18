#!/usr/bin/env python3
"""
followed_up_suricata_parser.py

Suricata equivalent of the Zeek followed_up_parser. It reads a client JSON/JSONL
and a Suricata eve.json. It classifies entries into "found" and "not found"
using source port + timestamp window (no DCID/SCID in eve.json).

Outputs (JSON arrays, same filenames/style as the Zeek variant):
  - found.json
  - not_found.json

Usage:
  python followed_up_suricata_parser.py --json <client.json|jsonl> --eve <eve.json> \
      --found found.json --notfound not_found.json [--window-seconds 1.0]
"""
import argparse
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

def _is_jsonl(path: str) -> bool:
    with open(path, "rb") as f:
        head = f.read(2).lstrip()
    return head[:1] != b'['

def _parse_timestamp(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    s = ts_str.strip().rstrip('Z')
    if '+' in s:
        s = s.split('+', 1)[0]
    if '.' in s:
        pre, frac = s.split('.', 1)
        frac = (frac + "000000")[:6]
        s = f"{pre}.{frac}"
        fmts = ["%Y-%m-%dT%H:%M:%S.%f"]
    else:
        fmts = ["%Y-%m-%dT%H:%M:%S"]
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None

def _load_json_or_jsonl(path: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if _is_jsonl(path):
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    items.append(obj)
                except json.JSONDecodeError:
                    continue
    else:
        with open(path, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                items.extend(data)
            else:
                raise ValueError(f"{path} is JSON but not an array")
    return items

def _normalize_client_entry(e: Dict[str, Any]) -> Dict[str, Any]:
    # ensure keys expected by other tools exist; carry existing bytes forward
    e.setdefault("domain", e.get("sni", "unknown"))
    e.setdefault("mutation_id", e.get("mutation", e.get("mut_id", "unknown")))
    e.setdefault("packet", e.get("packet", e.get("mutated", e.get("payload", ""))))
    e.setdefault("response", e.get("response", ""))
    e.setdefault("original", e.get("original", ""))
    e.setdefault("original_response", e.get("original_response", ""))
    e.setdefault("timestamp", e.get("timestamp", e.get("time", e.get("ts", ""))))
    # common sender port field
    if "src_port" not in e:
        for k in ("sport", "source_port", "src_p", "client_port"):
            if k in e:
                e["src_port"] = e[k]
                break
    # keep as string for robust comparison
    if "src_port" in e:
        e["src_port"] = str(e["src_port"])
    # normalize dest port if present
    if "port" in e:
        try:
            e["port"] = int(e["port"])
        except Exception:
            pass
    return e

def _extract_suricata_quic_entries(eve_path: str) -> List[Dict[str, Any]]:
    out = []
    with open(eve_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("event_type") != "quic":
                continue
            out.append(obj)
    return out

def _port_from_suricata(entry: Dict[str, Any]) -> Optional[str]:
    for k in ("src_port", "sport"):
        if k in entry:
            return str(entry[k])
    # nested inside "flow" or others
    for v in entry.values():
        if isinstance(v, dict):
            for k in ("src_port", "sport"):
                if k in v:
                    return str(v[k])
    return None

def _timestamp_from_suricata(entry: Dict[str, Any]) -> Optional[str]:
    # top-level timestamp
    if "timestamp" in entry:
        return entry["timestamp"]
    # sometimes in "flow" or elsewhere, but Suricata standard uses top-level
    for v in entry.values():
        if isinstance(v, dict) and "timestamp" in v:
            return v["timestamp"]
    return None

def _match_suricata_by_srcport_and_time(suri_entries: List[Dict[str, Any]], src_port: str, target_ts: datetime, window_sec: float) -> Optional[Dict[str, Any]]:
    best = None
    best_dt = None
    for e in suri_entries:
        sp = _port_from_suricata(e)
        if sp != src_port:
            continue
        ts_str = _timestamp_from_suricata(e)
        if not ts_str:
            continue
        ts = _parse_timestamp(ts_str)
        if not ts:
            continue
        dt = abs((ts - target_ts).total_seconds())
        if dt <= window_sec:
            if best is None or dt < best_dt:
                best = e
                best_dt = dt
    return best

def _safe_dump_json_array(path: str, items: List[Dict[str, Any]]):
    with open(path, "w") as f:
        json.dump(items, f, indent=2, sort_keys=False)

def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--json", required=True, help="Client JSON array or JSONL")
    ap.add_argument("--eve", required=True, help="Suricata eve.json (JSONL)")
    ap.add_argument("--found", required=True)
    ap.add_argument("--notfound", required=True)
    ap.add_argument("--window-seconds", type=float, default=1.0, help="Time window (+/- seconds) for matching")
    args = ap.parse_args()

    client_items = _load_json_or_jsonl(args.json)
    client_items = [_normalize_client_entry(dict(e)) for e in client_items]

    suri = _extract_suricata_quic_entries(args.eve)

    found: List[Dict[str, Any]] = []
    not_found: List[Dict[str, Any]] = []

    for e in client_items:
        ts = _parse_timestamp(e.get("timestamp", ""))
        sp = e.get("src_port")
        if not ts or not sp:
            not_found.append(e)
            continue

        match = _match_suricata_by_srcport_and_time(suri, sp, ts, args.window_seconds)

        if match:
            e_out = dict(e)  # carry existing fields/bytes forward
            e_out["suricata"] = {
                "timestamp": _timestamp_from_suricata(match),
                "src_ip": match.get("src_ip"),
                "src_port": _port_from_suricata(match),
                "dest_ip": match.get("dest_ip"),
                "dest_port": match.get("dest_port"),
                "app_proto": match.get("app_proto"),
                "event_type": match.get("event_type", "quic"),
            }
            found.append(e_out)
        else:
            not_found.append(e)

    _safe_dump_json_array(args.found, found)
    _safe_dump_json_array(args.notfound, not_found)

    print(f"Found: {len(found)}")
    print(f"Not found: {len(not_found)}")

if __name__ == "__main__":
    main()
