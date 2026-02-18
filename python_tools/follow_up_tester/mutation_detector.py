#!/usr/bin/env python3
"""
mutation_detector.py

Reads a client log (array or JSONL) and writes an enriched JSON with:
- Baseline: original + original_response
- Final: mutated/packet + response
- Smart byte-level diffs (original→mutated, original_response→response)
- QUIC header parse + header-diff (packet and response)
- Precursor support (ID ≥ 7 only):
    * precursor (hex strings, as given)
    * precursor_headers (parsed QUIC headers)
    * NOTE: no precursor comparisons/diffs are produced

Usage:
  python mutation_detector.py <input.json|jsonl> <output.json>
"""

import sys, json, difflib
from typing import Any, Dict, List, Optional, Tuple

# ------------------------------
# I/O helpers
# ------------------------------

def load_any_json(path: str) -> List[Dict[str, Any]]:
    """Load either a JSON array/single-object file or JSONL."""
    with open(path, "r") as f:
        raw = f.read().strip()
    if not raw:
        return []
    # Try standard JSON first
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    # Fallback: JSON Lines
    rows = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows

def save_json(path: str, obj: Any) -> None:
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)

# ------------------------------
# Diff helpers (hex-string diffs)
# ------------------------------

def _as_hex_str(s: Optional[str]) -> str:
    return (s or "").strip()

def smart_diff(hex_a: str, hex_b: str) -> List[Dict[str, Any]]:
    """
    Produce a compact diff between two hex strings.
    Returns a list of hunks with opcode and slices of the original hex.
    """
    a = _as_hex_str(hex_a)
    b = _as_hex_str(hex_b)
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    hunks = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        hunks.append({
            "op": tag,            # 'replace' | 'delete' | 'insert'
            "a_start": i1,
            "a_end": i2,
            "b_start": j1,
            "b_end": j2,
            "a_seg": a[i1:i2],
            "b_seg": b[j1:j2],
        })
    return hunks

def highlight_mutated(hex_a: str, hex_b: str) -> Dict[str, str]:
    """
    Very simple markup highlighting changes. Not perfect, but useful.
    Returns ANSI and HTML renderings of b with changed segments emphasized.
    """
    a = _as_hex_str(hex_a)
    b = _as_hex_str(hex_b)
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    parts_ansi = []
    parts_html = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        seg = b[j1:j2]
        if tag == "equal":
            parts_ansi.append(seg)
            parts_html.append(seg)
        else:
            parts_ansi.append("\x1b[1m\x1b[31m" + seg + "\x1b[0m")
            parts_html.append('<span style="font-weight:bold;">' + seg + "</span>")
    return {"ansi": "".join(parts_ansi), "html": "".join(parts_html)}

# ------------------------------
# QUIC header parsing (minimal + Length)
# ------------------------------

def _read_quic_varint(data: bytes, idx: int) -> Tuple[Optional[int], int, int]:
    """
    Read a QUIC varint at data[idx:].
    Returns (value, next_idx, size_bytes), or (None, idx, 0) on error.
    Size is 1, 2, 4, or 8 depending on top 2 bits of the first byte.
    """
    if idx >= len(data):
        return None, idx, 0
    first = data[idx]
    size = 1 << (first >> 6)  # 00->1, 01->2, 10->4, 11->8
    if idx + size > len(data):
        return None, idx, 0
    val = first & 0x3F
    for k in range(1, size):
        val = (val << 8) | data[idx + k]
    return val, idx + size, size

class QuicHeader:
    __slots__ = (
        "flags", "is_long", "version", "packet_type", "pn_length",
        "dcid", "scid", "token_len", "length", "length_size",
        "remaining"
    )
    def __init__(self):
        self.flags: Optional[int] = None
        self.is_long: bool = False
        self.version: Optional[int] = None
        self.packet_type: Optional[str] = None
        self.pn_length: Optional[int] = None
        self.dcid: Optional[str] = None
        self.scid: Optional[str] = None
        self.token_len: Optional[int] = None   # Initial only
        self.length: Optional[int] = None      # Long header except Retry
        self.length_size: Optional[int] = None # 1/2/4/8 bytes
        self.remaining: str = ""               # PN + payload (or the rest)

def parse_quic_header(hex_str: Optional[str]) -> Optional[QuicHeader]:
    s = _as_hex_str(hex_str)
    if not s:
        return None
    try:
        data = bytes.fromhex(s)
    except ValueError:
        return None
    if not data:
        return None

    h = QuicHeader()
    flags = data[0]
    h.flags = flags
    # Long header if bit 7 set
    h.is_long = bool(flags & 0x80)
    # Low 2 bits carry PN length (encoded as 0..3 => 1..4 bytes)
    h.pn_length = (flags & 0x03) + 1

    idx = 1
    if h.is_long:
        # Type from bits 5..4
        type_bits = (flags >> 4) & 0b11
        h.packet_type = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}.get(type_bits, "Long")

        # Need at least Version (4 bytes) present for long header
        if len(data) < idx + 4:
            h.remaining = data[idx:].hex()
            return h

        # Version
        h.version = int.from_bytes(data[idx:idx+4], "big")
        idx += 4

        # DCID
        if idx >= len(data):
            h.remaining = ""
            return h
        dlen = data[idx]; idx += 1
        if idx + dlen > len(data):
            h.remaining = ""
            return h
        h.dcid = data[idx:idx+dlen].hex()
        idx += dlen

        # SCID
        if idx >= len(data):
            h.remaining = ""
            return h
        slen = data[idx]; idx += 1
        if idx + slen > len(data):
            h.remaining = ""
            return h
        h.scid = data[idx:idx+slen].hex()
        idx += slen

        # Retry: no Length/PN, the rest is token + integrity tag
        if h.packet_type == "Retry":
            h.remaining = data[idx:].hex()
            return h

        # Initial has Token Length varint + Token
        if h.packet_type == "Initial":
            tlen, idx2, _tsz = _read_quic_varint(data, idx)
            if tlen is None or idx2 + tlen > len(data):
                h.remaining = data[idx:].hex()
                return h
            h.token_len = tlen
            idx = idx2 + tlen

        # Length varint (for Initial / 0-RTT / Handshake)
        lval, idx2, lsz = _read_quic_varint(data, idx)
        if lval is not None:
            h.length = lval
            h.length_size = lsz
            idx = idx2

        # Whatever remains (PN + payload)
        h.remaining = data[idx:].hex()
    else:
        # Short header (1-RTT): no DCID on wire; no Length field
        h.packet_type = "1-RTT"
        h.version = None
        h.dcid = ""
        h.scid = ""
        h.length = None
        h.length_size = None
        h.remaining = data[1:].hex()

    return h

def header_to_dict(h: Optional[QuicHeader]) -> Optional[Dict[str, Any]]:
    if not h:
        return None
    return {
        "flags": h.flags,
        "is_long": h.is_long,
        "version": h.version,
        "packet_type": h.packet_type,
        "pn_length": h.pn_length,
        "dcid": h.dcid or "",
        "scid": h.scid or "",
        "token_len": h.token_len,                 # Initial only
        "length": h.length,                       # QUIC header Length
        "length_varint_bytes": h.length_size,     # 1/2/4/8
        "remaining_payload": h.remaining,
    }

def header_changes(h0: Optional[QuicHeader], h1: Optional[QuicHeader]) -> List[Dict[str, Any]]:
    d0 = header_to_dict(h0) or {}
    d1 = header_to_dict(h1) or {}
    keys = sorted(set(d0.keys()) | set(d1.keys()))
    out = []
    for k in keys:
        if d0.get(k) != d1.get(k):
            out.append({"field": k, "from": d0.get(k), "to": d1.get(k)})
    return out

def mutation_name(mid: Any) -> str:
    NAMES = {
        1: "MutateVersionSpoofing",
        2: "MutatePaddingDCID",
        3: "MutatePaddingSCID",
        4: "Mutate0RTTInjection",
        5: "MutateHeaderFlagsFlip",
        6: "MutateLengthTamper",
        7: "Precursor0RTTThenInitial",
        8: "PrecursorHandshakeThenInitial",
        9: "PrecursorRetryThenInitial",
        10: "PrecursorVersionNegotiation",
    }
    try:
        mid_i = int(mid)
        return NAMES.get(mid_i, f"Mutation{mid_i}")
    except Exception:
        return str(mid)

# ------------------------------
# Main
# ------------------------------

def main():
    if len(sys.argv) != 3:
        print("Usage: python mutation_detector.py <input.json|jsonl> <output.json>")
        sys.exit(1)
    in_path, out_path = sys.argv[1], sys.argv[2]

    rows = load_any_json(in_path)
    out_rows: List[Dict[str, Any]] = []

    for rec in rows:
        original = _as_hex_str(rec.get("original"))
        mutated  = _as_hex_str(rec.get("mutated") or rec.get("packet"))
        original_resp = _as_hex_str(rec.get("original_response"))
        mutated_resp  = _as_hex_str(rec.get("response"))

        # Parse mutation id once
        try:
            mid = int(rec.get("mutation_id", 0))
        except Exception:
            mid = 0

        # Drop if non-precursor (mutation_id < 7) and packet unchanged
        if mid < 7 and original == mutated:
            continue

        # Diffs (baseline vs final)
        pkt_diff  = smart_diff(original, mutated)
        resp_diff = smart_diff(original_resp, mutated_resp)

        # Packet header analysis (now includes token_len/length for long hdrs)
        h0 = parse_quic_header(original)
        h1 = parse_quic_header(mutated)
        hdr_orig = header_to_dict(h0)
        hdr_mut  = header_to_dict(h1)
        hdr_changes = header_changes(h0, h1)

        # Response header analysis
        hr0 = parse_quic_header(original_resp)
        hr1 = parse_quic_header(mutated_resp)
        resp_hdr_orig = header_to_dict(hr0)
        resp_hdr_mut  = header_to_dict(hr1)
        resp_hdr_changes = header_changes(hr0, hr1)

        # Highlight changes in final mutated textually
        highlights = highlight_mutated(original, mutated)

        # ----- Precursor support (ID ≥ 7 only; no diffs) -----
        precursor_hex = None
        precursor_headers = None
        if mid >= 7:
            prec_list = rec.get("precursor")
            if isinstance(prec_list, list) and prec_list:
                precursor_hex = [_as_hex_str(p) for p in prec_list]
                precursor_headers = [header_to_dict(parse_quic_header(p)) for p in precursor_hex]

        row_out: Dict[str, Any] = {
            # Metadata
            "timestamp": rec.get("timestamp"),
            "domain": rec.get("domain"),
            "mutation_id": rec.get("mutation_id"),
            "mutation_name": mutation_name(rec.get("mutation_id")),

            # Baseline & final bytes
            "original": original,
            "mutated": mutated,

            # Diffs
            "packet_diff": pkt_diff,
            "packet_num_diff_hunks": len(pkt_diff),

            # Responses
            "original_response": original_resp,
            "response": mutated_resp,
            "response_diff": resp_diff,
            "response_num_diff_hunks": len(resp_diff),

            # Headers (packet)
            "packet_header_original": hdr_orig,
            "packet_header_mutated":  hdr_mut,
            "packet_header_changes":  hdr_changes,

            # Headers (response)
            "response_header_original": resp_hdr_orig,
            "response_header_mutated":  resp_hdr_mut,
            "response_header_changes":  resp_hdr_changes,

            # Visual hint for mutated differences
            "packet_mutated_highlight_ansi": highlights.get("ansi"),
            "packet_mutated_highlight_html": highlights.get("html"),
        }

        # Attach precursors (ID ≥ 7) without comparisons
        if precursor_hex:
            row_out["precursor"] = precursor_hex
            row_out["precursor_headers"] = precursor_headers

        out_rows.append(row_out)

    save_json(out_path, out_rows)
    print(f"[✓] Wrote {len(out_rows)} rows to {out_path}")

if __name__ == "__main__":
    main()
