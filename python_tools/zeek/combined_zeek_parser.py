"""
Usage:
  python combined_zeek_parser_dedup.py <client_input.json> <zeek_quic.log> \
      <found.json> <not_found.json> <responded_missing.json> <responded_matched.json>
"""
from __future__ import annotations
import json
import csv
import sys
import hashlib
from typing import Dict, Any, List, Tuple, Optional, Set

# -------------------------------
# PART 1: Client log ingestion
# -------------------------------

def extract_packets(input_file: str) -> List[Dict[str, Any]]:
    """
    Read line-delimited JSON client log and return a list of packet dicts.

    FIXES:
    - If original/original_response are on a different line than the mutated/response,
      attach the most recent original/original_response seen for the same (domain, mutation_id).
    - NEW: Carry through `precursor` (list of hex strings) if present on mutated entries.
    """
    # ---- pass 0: load all lines ----
    raw_entries: List[Dict[str, Any]] = []
    with open(input_file, 'r') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                raw_entries.append(entry)
            except json.JSONDecodeError:
                continue

    # ---- pass 1: cache the latest original/original_response per key ----
    # Key choice: (domain, mutation_id). If you have a better correlation id, swap it in.
    orig_cache: Dict[Tuple[str, int], Dict[str, str]] = {}
    for e in raw_entries:
        original = e.get("original")
        if not original:
            continue
        key = (str(e.get("domain")), int(e.get("mutation_id") or 0))
        cache_val = {"original": str(original)}
        if e.get("original_response"):
            cache_val["original_response"] = str(e["original_response"])
        # Always keep the most recent seen (by file order)
        orig_cache[key] = cache_val

    # ---- pass 2: emit records, attaching cached originals when missing ----
    extracted: List[Dict[str, Any]] = []
    for e in raw_entries:
        base = {
            "mutation_id": e.get("mutation_id"),
            "domain": e.get("domain"),
            "timestamp": e.get("timestamp"),
        }
        key = (str(base["domain"]), int(base["mutation_id"] or 0))

        # Build passthrough: prefer inline original/original_response; else use cache
        passthrough: Dict[str, Any] = {}
        if e.get("original"):
            passthrough["original"] = str(e["original"])
            if e.get("original_response"):
                passthrough["original_response"] = str(e["original_response"])
        elif key in orig_cache:
            passthrough.update(orig_cache[key])

        original = e.get("original")
        mutated = e.get("mutated")
        response = e.get("response")

        if original:
            extracted.append({
                **base, **passthrough,
                "source": "original",
                "packet": str(original),
            })

        if mutated:
            obj: Dict[str, Any] = {
                **base, **passthrough,
                "source": "mutated",
                "packet": str(mutated),
            }
            # NEW: carry precursor[] context if present (list of hex strings)
            if isinstance(e.get("precursor"), list):
                obj["precursor"] = [str(x) for x in e["precursor"]]
            if response:
                obj["response"] = str(response)
            extracted.append(obj)

    return extracted

# -------------------------------
# PART 2: Zeek quic.log parsing
# -------------------------------

def parse_zeek_log(path: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    with open(path, 'r') as f:
        reader = csv.reader(f, delimiter='\t')
        header: Optional[List[str]] = None
        for row in reader:
            if not row:
                continue
            first = row[0]
            if first.startswith("#fields"):
                header = row[1:]
                continue
            if first.startswith("#") or not header:
                continue
            entries.append(dict(zip(header, row)))
    return entries

# -------------------------------
# PART 3: Minimal QUIC header parser
# -------------------------------

class QuicHeader:
    __slots__ = (
        "flags", "is_long", "version", "packet_type", "pn_length",
        "dcid", "scid", "remaining",
        "bits",  # convenience dict of individual first-byte bits b7..b0
    )
    def __init__(self):
        self.flags: int = 0
        self.is_long: bool = False
        self.version: Optional[int] = None
        self.packet_type: Optional[str] = None
        self.pn_length: Optional[int] = None
        self.dcid: Optional[str] = None
        self.scid: Optional[str] = None
        self.remaining: str = ""
        self.bits: Dict[str, int] = {}

def parse_quic_header(hex_str: str) -> Optional[QuicHeader]:
    try:
        data = bytes.fromhex(hex_str)
        if not data:
            return None
        h = QuicHeader()
        flags = data[0]
        h.flags = flags
        # Pre-split bits for convenience (b7 is MSB)
        h.bits = {f"b{i}": (flags >> i) & 1 for i in range(8)}
        # Header form: b7 (1 = long, 0 = short)
        h.is_long = bool(flags & 0x80)
        idx = 1
        if h.is_long:
            # Long header byte layout (RFC 9000):
            # b7=1 (LH), b6=Fixed, b5.b4=Type, b3.b2=Reserved, b1.b0=PN len - 1
            type_bits = (flags >> 4) & 0b11
            h.packet_type = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}.get(type_bits, "Long")
            h.pn_length = (flags & 0x03) + 1
            if len(data) < 6:
                return h
            # Version
            h.version = int.from_bytes(data[idx:idx+4], 'big')
            idx += 4
            # DCID
            if idx >= len(data): return h
            dlen = data[idx]; idx += 1
            if idx + dlen > len(data): return h
            h.dcid = data[idx:idx+dlen].hex()
            idx += dlen
            # SCID
            if idx >= len(data): return h
            slen = data[idx]; idx += 1
            if idx + slen > len(data): return h
            h.scid = data[idx:idx+slen].hex()
            idx += slen
            # Remaining payload (for convenience in signatures)
            h.remaining = data[idx:].hex()
        else:
            # Short header: DCID not present; infer nothing here
            h.packet_type = "1-RTT"
            h.remaining = data[1:].hex()
        return h
    except Exception:
        return None

# -------------------------------
# PART 4: Zeek match helpers
# -------------------------------

def match_id_to_zeek(val: str, zeek_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    val_l = (val or "").lower()
    out = []
    for r in zeek_rows:
        # Prefer server_scid, but accept client_initial_dcid/server_scid if present
        for k in ("server_scid", "client_initial_dcid", "client_scid"):
            v = (r.get(k) or "").lower()
            if v and v == val_l:
                out.append(r)
                break
    return out

# -------------------------------
# PART 5: Mutation signatures for response dedupe
# -------------------------------

def sig_header_flags_flip(pkt_hex: str, hdr: QuicHeader) -> str:
    """3-bit signature for mutation_id=5 (Header flags flip)."""
    if not hdr:
        return "ERR:---"
    if hdr.is_long:
        b3 = (hdr.flags >> 3) & 1
        b2 = (hdr.flags >> 2) & 1
        b0 = (hdr.flags >> 0) & 1
        return f"LH:{b3}{b2}{b0}"
    else:
        b4 = (hdr.flags >> 4) & 1
        b3 = (hdr.flags >> 3) & 1
        b2 = (hdr.flags >> 2) & 1
        return f"SH:{b4}{b3}{b2}"

def sig_fallback(pkt_hex: str, hdr: Optional[QuicHeader]) -> str:
    """Conservative fallback: hash of first byte."""
    try:
        b0 = bytes.fromhex(pkt_hex)[:1]
        return hashlib.sha1(b0).hexdigest()[:8]
    except Exception:
        return "00000000"

MUTATION_SIGNATURES = {
    5: sig_header_flags_flip,  # HeaderFlagsFlip
    # Add more mutation_id -> extractor here later
}

# -------------------------------
# PART 6: Main routine
# -------------------------------

def main(client_input_path: str, zeek_log_path: str,
         output_found_path: str, output_not_found_path: str,
         output_responded_missing_path: str, output_responded_matched_path: str) -> None:

    print("[*] Parsing Zeek log…")
    zeek_entries = parse_zeek_log(zeek_log_path)

    print("[*] Reading client log…")
    entries = extract_packets(client_input_path)

    print("[*] Parsing headers and precomputing match keys…")
    enriched: List[Dict[str, Any]] = []
    for e in entries:
        pkt_hex = e.get("packet") or ""
        hdr = parse_quic_header(pkt_hex)
        e2 = dict(e)  # includes precursor[] if present
        if hdr:
            e2["parsed_header"] = {
                "is_long": hdr.is_long,
                "flags": hdr.flags,
                "version": hdr.version,
                "packet_type": hdr.packet_type,
                "pn_length": hdr.pn_length,
                "dcid": hdr.dcid or "",
                "scid": hdr.scid or "",
            }
            e2["dcid"] = hdr.dcid or e.get("dcid")
            e2["scid"] = hdr.scid or e.get("scid")
        else:
            e2["parsed_header"] = None
        enriched.append(e2)

    # Classify found vs not_found based on Zeek match (DCID preferred; fallback SCID)
    found: List[Dict[str, Any]] = []
    not_found: List[Dict[str, Any]] = []
    for e in enriched:
        dcid = (e.get("dcid") or "").lower()
        scid = (e.get("scid") or "").lower()
        matches = []
        if dcid:
            matches = match_id_to_zeek(dcid, zeek_entries)
        if not matches and scid:
            matches = match_id_to_zeek(scid, zeek_entries)
        if matches:
            e_copy = dict(e)
            e_copy["zeek_matches"] = matches
            found.append(e_copy)
        else:
            not_found.append(e)

    # Response-only deduplication (on *responses* only)
    print("[*] Aggregating responses with mutation-specific dedupe (responses only)…")
    responded_missing: List[Dict[str, Any]] = []
    responded_matched: List[Dict[str, Any]] = []

    # Track seen signatures per (domain, mutation_id) ONLY for responded entries
    seen_resp_sigs: Dict[Tuple[str, int], Set[str]] = {}

    def get_sig(e: Dict[str, Any]) -> str:
        mid = e.get("mutation_id")
        pkt_hex = e.get("packet") or ""
        hdr = parse_quic_header(pkt_hex)
        fn = MUTATION_SIGNATURES.get(mid, sig_fallback)
        return fn(pkt_hex, hdr)

    for e in enriched:
        if "response" not in e or not e["response"]:
            continue
        key = (str(e.get("domain")), int(e.get("mutation_id") or 0))
        sig = get_sig(e)
        if key not in seen_resp_sigs:
            seen_resp_sigs[key] = set()
        if sig in seen_resp_sigs[key]:
            # Duplicate in *responses* for this mutation/domain → drop from response logs
            continue
        seen_resp_sigs[key].add(sig)

        # reclassify as responded_matched vs responded_missing
        dcid = (e.get("dcid") or "").lower()
        scid = (e.get("scid") or "").lower()
        matched = False
        if dcid and match_id_to_zeek(dcid, zeek_entries):
            matched = True
        elif scid and match_id_to_zeek(scid, zeek_entries):
            matched = True
        if matched:
            responded_matched.append(e)
        else:
            responded_missing.append(e)

    # Write outputs
    with open(output_found_path, 'w') as f:
        json.dump(found, f, indent=2)
    print(f"[✓] Wrote {len(found)} matched packets to {output_found_path}")

    with open(output_not_found_path, 'w') as f:
        json.dump(not_found, f, indent=2)
    print(f"[✓] Wrote {len(not_found)} unmatched packets to {output_not_found_path}")

    with open(output_responded_missing_path, 'w') as f:
        json.dump(responded_missing, f, indent=2)
    print(f"[✓] Wrote {len(responded_missing)} response (no Zeek match) to {output_responded_missing_path}")

    with open(output_responded_matched_path, 'w') as f:
        json.dump(responded_matched, f, indent=2)
    print(f"[✓] Wrote {len(responded_matched)} response (with Zeek match) to {output_responded_matched_path}")

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("Usage: python combined_zeek_parser_dedup.py <client_input.json> <zeek_quic.log> "
              "<found.json> <not_found.json> <responded_missing.json> <responded_matched.json>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
