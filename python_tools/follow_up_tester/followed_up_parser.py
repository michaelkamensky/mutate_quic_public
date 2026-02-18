#!/usr/bin/env python3
import json
import argparse

def load_input_log(json_file):
    """
    Accepts either:
      - a JSON array, or
      - JSON Lines (one object per line).
    Returns a list of dicts.
    """
    with open(json_file, 'r') as f:
        content = f.read().strip()
        if not content:
            return []
        # Try standard JSON (array or single object)
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass

    # Fallback to JSONL
    out = []
    with open(json_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out

def load_zeek_log(zeek_file):
    """
    Returns a set of server_scid values from a Zeek quic.log (TSV with #fields header).
    If no header is found, falls back to column index 9.
    """
    scids = set()
    idx_server_scid = None
    with open(zeek_file, 'r') as f:
        for raw in f:
            line = raw.rstrip('\n')
            if not line or line.startswith('#'):
                # Parse header mapping if available
                if line.startswith('#fields'):
                    # e.g. "#fields\tts\tuid\t...\tserver_scid\t..."
                    parts = line.split('\t')[1:]  # drop "#fields"
                    try:
                        idx_server_scid = parts.index('server_scid')
                    except ValueError:
                        idx_server_scid = None
                continue

            fields = line.split('\t')
            # Fallback if header missing
            if idx_server_scid is None:
                if len(fields) > 9:
                    val = fields[9].strip().lower()
                    if val and val != '-':
                        scids.add(val)
                continue

            if len(fields) > idx_server_scid:
                val = fields[idx_server_scid].strip().lower()
                if val and val != '-':
                    scids.add(val)
    return scids

def normalize_entry(entry):
    """
    Ensure the key fields are present on the output record:
      - original, original_response, packet, response
      - NEW: carry through precursor[] if present
    Prefer 'packet' if present; else fall back to 'mutated' for the packet payload.
    """
    e = dict(entry)  # shallow copy to preserve everything else
    e.setdefault('original', entry.get('original', ''))
    e.setdefault('original_response', entry.get('original_response', ''))
    # 'packet' may already exist in your pipeline; if not, try 'mutated'
    e['packet'] = entry.get('packet') if entry.get('packet') is not None else entry.get('mutated', '')
    e.setdefault('response', entry.get('response', ''))
    # Preserve precursor sequencing if present (expect hex strings)
    prec = entry.get('precursor')
    if isinstance(prec, list):
        e['precursor'] = [str(x) for x in prec]
    return e

def match_entries(input_data, zeek_scids):
    found, not_found = [], []
    for entry in input_data:
        # SCID extracted from the *response_header* (if present)
        scid = (entry.get("response_header", {}) or {}).get("scid", "")
        scid = scid.lower() if isinstance(scid, str) else ""
        if scid and scid in zeek_scids:
            found.append(normalize_entry(entry))
        else:
            not_found.append(normalize_entry(entry))
    return found, not_found

def main(json_path, zeek_log_path, found_out, not_found_out):
    print(f"[+] Loading input log from: {json_path}")
    input_data = load_input_log(json_path)

    print(f"[+] Loading Zeek SCIDs from: {zeek_log_path}")
    zeek_scids = load_zeek_log(zeek_log_path)

    print(f"[+] Matching SCIDs...")
    found, not_found = match_entries(input_data, zeek_scids)

    with open(found_out, 'w') as f:
        json.dump(found, f, indent=2)
    with open(not_found_out, 'w') as f:
        json.dump(not_found, f, indent=2)

    print(f"[✓] Found: {len(found)} entries written to {found_out}")
    print(f"[✓] Not Found: {len(not_found)} entries written to {not_found_out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Match SCIDs in QUIC logs and preserve original/mutated fields + precursor sequence.")
    parser.add_argument("--json", required=True, help="Input JSON or JSONL log file")
    parser.add_argument("--zeek", required=True, help="Input Zeek quic.log file")
    parser.add_argument("--found", default="found.json", help="Output JSON for matched entries")
    parser.add_argument("--notfound", default="not_found.json", help="Output JSON for unmatched entries")
    args = parser.parse_args()

    main(args.json, args.zeek, args.found, args.notfound)
