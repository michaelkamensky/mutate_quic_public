
#!/usr/bin/env python3
"""combined_suricata_parser.py

Initial Suricata pass: join Suricata-client entries to ORIGINAL client log to
carry byte fields (packet/response/original/original_response), then confirm
detection in eve.json using src_port + timestamp window (optionally tightened
by dest_ip/port and SNI).

Inputs:
  1) original_client_log (JSON/JSONL; contains mutated + original bytes)
  2) suricata_client_log (JSON/JSONL; dcid/src_port/timestamp)
  3) eve.json (JSONL)

Outputs:
  - found.json
  - not_found.json
  - responded_missing.json
  - responded_matched.json
"""
import argparse
from typing import List, Dict, Any, Tuple, Optional

import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional

# --------------- Loaders & time parsing ---------------

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
        frac = (frac + "000000")[:6]  # microseconds
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

# --------------- Client normalization ---------------

def _normalize_client_entry(e: Dict[str, Any]) -> Dict[str, Any]:
    e = dict(e)  # copy
    e.setdefault("domain", e.get("sni", "unknown"))
    e.setdefault("mutation_id", e.get("mutation", e.get("mut_id", "unknown")))
    e.setdefault("packet", e.get("mutated", e.get("payload", "")))  # mutated
    e.setdefault("response", e.get("response", ""))                 # mutated response
    e.setdefault("original", e.get("original", ""))
    e.setdefault("original_response", e.get("original_response", ""))
    e.setdefault("timestamp", e.get("time", e.get("ts", "")))
    # src_port normalization
    if "src_port" not in e:
        for k in ("sport", "source_port", "src_p", "client_port"):
            if k in e:
                e["src_port"] = e[k]
                break
    if "src_port" in e:
        e["src_port"] = str(e["src_port"])
    # dest port normalization
    if "port" in e:
        try:
            e["port"] = int(e["port"])
        except Exception:
            pass
    # dcid passthrough if present
    if "dcid" in e and isinstance(e["dcid"], str):
        e["dcid"] = e["dcid"].lower()
    return e

def _has_response(e: Dict[str, Any]) -> bool:
    def _nonempty(x: Any) -> bool:
        return isinstance(x, str) and len(x) > 0
    return _nonempty(e.get("response", "")) or _nonempty(e.get("original_response", ""))

# --------------- Suricata helpers ---------------

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

def _nested_get(d: Dict[str, Any], *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def _port_from_suricata(entry: Dict[str, Any]) -> Optional[str]:
    for k in ("src_port", "sport"):
        if k in entry:
            return str(entry[k])
    # nested
    for v in entry.values():
        if isinstance(v, dict):
            for k in ("src_port", "sport"):
                if k in v:
                    return str(v[k])
    return None

def _dest_port_from_suricata(entry: Dict[str, Any]) -> Optional[int]:
    if "dest_port" in entry:
        try:
            return int(entry["dest_port"])
        except Exception:
            return None
    # nested
    for v in entry.values():
        if isinstance(v, dict) and "dest_port" in v:
            try:
                return int(v["dest_port"])
            except Exception:
                return None
    return None

def _src_ip_from_suricata(entry: Dict[str, Any]) -> Optional[str]:
    return entry.get("src_ip") or _nested_get(entry, "flow", "src_ip", default=None)

def _dest_ip_from_suricata(entry: Dict[str, Any]) -> Optional[str]:
    return entry.get("dest_ip") or _nested_get(entry, "flow", "dest_ip", default=None)

def _sni_from_suricata(entry: Dict[str, Any]) -> Optional[str]:
    sni = _nested_get(entry, "quic", "sni", default=None)
    if isinstance(sni, str) and sni:
        return sni.lower()
    return None

def _timestamp_from_suricata(entry: Dict[str, Any]) -> Optional[str]:
    if "timestamp" in entry:
        return entry["timestamp"]
    for v in entry.values():
        if isinstance(v, dict) and "timestamp" in v:
            return v["timestamp"]
    return None

def _match_suricata_event(e: Dict[str, Any], suri_entries: List[Dict[str, Any]], window_sec: float) -> Optional[Dict[str, Any]]:
    """Match eve.json by (src_port) + optional (dest_ip/port, SNI) + timestamp window."""
    target_ts = _parse_timestamp(e.get("timestamp", ""))
    if not target_ts:
        return None
    src_port = e.get("src_port")
    if not src_port:
        return None

    want_dest_ip = (e.get("ip") or e.get("dest_ip"))
    want_dest_port = e.get("port")
    want_domain = (e.get("domain") or e.get("sni"))
    want_domain = want_domain.lower() if isinstance(want_domain, str) else None

    best = None
    best_dt = None

    for ev in suri_entries:
        sp = _port_from_suricata(ev)
        if sp != src_port:
            continue

        ev_dport = _dest_port_from_suricata(ev)
        if want_dest_port is not None and ev_dport is not None and ev_dport != want_dest_port:
            continue

        ev_dip = _dest_ip_from_suricata(ev)
        if want_dest_ip and ev_dip and str(ev_dip) != str(want_dest_ip):
            continue

        ev_sni = _sni_from_suricata(ev)
        if want_domain and ev_sni and ev_sni != want_domain:
            continue

        ts_str = _timestamp_from_suricata(ev)
        if not ts_str:
            continue
        ts = _parse_timestamp(ts_str)
        if not ts:
            continue
        dt = abs((ts - target_ts).total_seconds())
        if dt <= window_sec:
            if best is None or dt < best_dt:
                best = ev
                best_dt = dt

    return best

def _safe_dump_json_array(path: str, items: List[Dict[str, Any]]):
    with open(path, "w") as f:
        json.dump(items, f, indent=2, sort_keys=False)


# --------------- Original cache ---------------

def _build_original_cache(originals: List[Dict[str, Any]]) -> Dict[Tuple[str, str, Optional[str]], List[Dict[str, Any]]]:
    """Index originals by (domain, mutation_id, dcid [optional]). Value is a list to allow multiple attempts."""
    cache: Dict[Tuple[str, str, Optional[str]], List[Dict[str, Any]]] = {}
    for e in originals:
        en = _normalize_client_entry(e)
        dom = str(en.get("domain", "unknown"))
        mid = str(en.get("mutation_id", "unknown"))
        dcid = en.get("dcid")
        key_specific = (dom, mid, dcid) if dcid else None
        key_fallback = (dom, mid, None)

        for k in (key_fallback, key_specific):
            if k is None: 
                continue
            cache.setdefault(k, []).append(en)
    return cache

def _score_original_candidate(suri_item: Dict[str, Any], cand: Dict[str, Any]) -> Tuple[int, float]:
    """Higher score is better; lower time delta is better.
       +2 if dest ip matches, +1 if dest port matches, +1 if domain matches.
       Time delta in seconds for tie-break (smaller is better)."""
    score = 0
    if suri_item.get("ip") and cand.get("ip") and str(suri_item["ip"]) == str(cand["ip"]):
        score += 2
    if suri_item.get("port") and cand.get("port") and int(suri_item["port"]) == int(cand["port"]):
        score += 1
    dom_a = (suri_item.get("domain") or "").lower()
    dom_b = (cand.get("domain") or "").lower()
    if dom_a and dom_b and dom_a == dom_b:
        score += 1

    t1 = _parse_timestamp(suri_item.get("timestamp", ""))
    t2 = _parse_timestamp(cand.get("timestamp", ""))
    dt = abs((t1 - t2).total_seconds()) if (t1 and t2) else 999999.0
    return score, dt

def _merge_original_fields(target: Dict[str, Any], orig: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(target)
    # mutated bytes
    if not out.get("packet"):
        out["packet"] = orig.get("packet", "")
    if not out.get("response"):
        out["response"] = orig.get("response", "")
    # original bytes
    if not out.get("original"):
        out["original"] = orig.get("original", "")
    if not out.get("original_response"):
        out["original_response"] = orig.get("original_response", "")
    # headers if present
    for k in ("original_header", "original_response_header", "packet_header", "response_header"):
        if k not in out and k in orig:
            out[k] = orig[k]
    return out

# --------------- Main ---------------

def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("original_client_log", help="Original client log (JSON/JSONL) with byte fields")
    ap.add_argument("suricata_client_log", help="Suricata-phase client log (JSON/JSONL)")
    ap.add_argument("eve_json", help="Suricata eve.json (JSONL)")
    ap.add_argument("found_out")
    ap.add_argument("not_found_out")
    ap.add_argument("responded_missing_out")
    ap.add_argument("responded_matched_out")
    ap.add_argument("--window-seconds", type=float, default=1.0, help="Time window (+/- seconds) for eve.json matching")
    args = ap.parse_args()

    originals_raw = _load_json_or_jsonl(args.original_client_log)
    suri_client_raw = _load_json_or_jsonl(args.suricata_client_log)
    suri_eve = _extract_suricata_quic_entries(args.eve_json)

    orig_cache = _build_original_cache(originals_raw)

    # Join Suricata client items to ORIGINAL records to attach bytes
    clients: List[Dict[str, Any]] = []
    for e in suri_client_raw:
        en = _normalize_client_entry(e)
        dom = str(en.get("domain", "unknown"))
        mid = str(en.get("mutation_id", "unknown"))
        dcid = en.get("dcid")
        candidates = []
        # specific then fallback
        if dcid:
            candidates.extend(orig_cache.get((dom, mid, dcid), []))
        candidates.extend(orig_cache.get((dom, mid, None), []))

        if candidates:
            # choose best candidate by score, then by nearest timestamp
            scored = sorted(((_score_original_candidate(en, c), c) for c in candidates),
                            key=lambda t: (-t[0][0], t[0][1]))
            best = scored[0][1]
            en = _merge_original_fields(en, best)

        clients.append(en)

    found: List[Dict[str, Any]] = []
    not_found: List[Dict[str, Any]] = []
    responded_missing: List[Dict[str, Any]] = []
    responded_matched: List[Dict[str, Any]] = []

    for e in clients:
        match = _match_suricata_event(e, suri_eve, args.window_seconds)

        if match is not None:
            e_out = dict(e)
            e_out["suricata"] = {
                "timestamp": _timestamp_from_suricata(match),
                "src_ip": _src_ip_from_suricata(match),
                "src_port": _port_from_suricata(match),
                "dest_ip": _dest_ip_from_suricata(match),
                "dest_port": _dest_port_from_suricata(match),
                "sni": _sni_from_suricata(match),
                "app_proto": match.get("app_proto"),
                "event_type": match.get("event_type", "quic"),
            }
            found.append(e_out)
            if _has_response(e_out):
                responded_matched.append(e_out)
        else:
            not_found.append(e)
            if _has_response(e):
                responded_missing.append(e)

    _safe_dump_json_array(args.found_out, found)
    _safe_dump_json_array(args.not_found_out, not_found)
    _safe_dump_json_array(args.responded_missing_out, responded_missing)
    _safe_dump_json_array(args.responded_matched_out, responded_matched)

    print(f"Matches: {len(found)}")
    print(f"Not found: {len(not_found)}")
    print(f"Responded (missing): {len(responded_missing)}")
    print(f"Responded (matched): {len(responded_matched)}")

if __name__ == "__main__":
    main()