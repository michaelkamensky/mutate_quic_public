#!/usr/bin/env python3
import argparse
import json
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

def _is_json_array_file(path: str) -> bool:
    with open(path, "rb") as f:
        while True:
            ch = f.read(1)
            if not ch:
                return False
            if chr(ch[0]).isspace():
                continue
            return chr(ch[0]) == "["

def _iter_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError as e:
                raise SystemExit(f"Invalid JSONL line: {e}: {s[:200]}")
            if not isinstance(obj, dict):
                raise SystemExit("Each JSONL line must be a JSON object")
            yield obj

def _iter_json_array(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise SystemExit(f"Invalid JSON: {e}")
    if isinstance(data, list):
        for i, obj in enumerate(data):
            if not isinstance(obj, dict):
                raise SystemExit(f"Array element #{i} is not an object")
            yield obj
    elif isinstance(data, dict):
        # Single object file; treat as one-entry array
        yield data
    else:
        raise SystemExit("Top-level JSON must be an object or array")

_hex_re = re.compile(r"^[0-9A-Fa-f]+$")

def _norm_val(v: Any) -> Any:
    if v is None:
        return None
    s = str(v).strip()
    if _hex_re.fullmatch(s):
        return s.lower()
    return s

def _canonical_signature(entry: Dict[str, Any]) -> Optional[str]:
    changes = entry.get("packet_header_changes", None)
    if not changes or not isinstance(changes, list):
        # Missing or empty => use None to signal special rule handling
        return None

    triples: List[Tuple[str, Any, Any]] = []
    for ch in changes:
        if not isinstance(ch, dict):
            # If malformed, treat entire entry as having missing/empty changes
            return None
        field = ch.get("field", None)
        frm = ch.get("from", None)
        to = ch.get("to", None)
        triples.append((str(field), _norm_val(frm), _norm_val(to)))

    # Order-insensitive: sort the triples
    triples.sort(key=lambda t: (t[0], "" if t[1] is None else str(t[1]), "" if t[2] is None else str(t[2])))
    return json.dumps(triples, separators=(",", ":"))

def _should_keep_when_missing(entry: Dict[str, Any]) -> bool:
    # Special rule: if packet_header_changes is missing/empty,
    # keep ONLY if mutation_id >= 7; otherwise drop.
    mid = entry.get("mutation_id", None)
    try:
        return mid is not None and int(mid) >= 7
    except Exception:
        return False

def process(input_path: str, output_path: str) -> Tuple[int, int, int]:
    is_array = _is_json_array_file(input_path)
    seen = set()
    kept: List[Dict[str, Any]] = []
    read = kept_count = dropped = 0

    iterator = _iter_json_array(input_path) if is_array else _iter_jsonl(input_path)
    for entry in iterator:
        read += 1
        sig = _canonical_signature(entry)
        if sig is None:
            if _should_keep_when_missing(entry):
                kept.append(entry)
                kept_count += 1
            else:
                dropped += 1
        else:
            if sig in seen:
                dropped += 1
            else:
                seen.add(sig)
                kept.append(entry)
                kept_count += 1

    # Write output in same format as input
    if is_array:
        with open(output_path, "w", encoding="utf-8") as out:
            json.dump(kept, out, ensure_ascii=False, indent=2)
            out.write("\n")
    else:
        with open(output_path, "w", encoding="utf-8") as out:
            for obj in kept:
                out.write(json.dumps(obj, ensure_ascii=False))
                out.write("\n")

    return read, kept_count, dropped

def main():
    ap = argparse.ArgumentParser(description="Remove duplicates by packet_header_changes; missing/empty kept only if mutation_id >= 7.")
    ap.add_argument("input", help="Input log (JSONL or JSON array)")
    ap.add_argument("output", help="Output log (same format as input)")
    args = ap.parse_args()

    read, kept, dropped = process(args.input, args.output)
    print(f"Read: {read}; Kept: {kept}; Dropped: {dropped}", file=sys.stderr)

if __name__ == "__main__":
    main()