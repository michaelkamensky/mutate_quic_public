import sys
import json
from datetime import datetime

def parse_timestamp(ts_str):
    # Remove timezone (Z or +0000) if present
    ts_str = ts_str.rstrip('Z').split('+')[0]

    # Truncate nanoseconds to microseconds if >6 digits
    if '.' in ts_str:
        prefix, frac = ts_str.split('.')
        frac = (frac + "000000")[:6]  # pad and trim to 6 digits
        ts_str = f"{prefix}.{frac}"
    try:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")

def src_port_match(entry, port):
    """Check only source port fields"""
    src_keys = ['src_port', 'sport', 'id.orig_p']
    for key in src_keys:
        if key in entry and str(entry[key]) == str(port):
            return True
    for _, v in entry.items():
        if isinstance(v, dict):
            for subk, subv in v.items():
                if subk in src_keys and str(subv) == str(port):
                    return True
    return False

def timestamp_match(entry_time_str, target_time):
    try:
        entry_time = parse_timestamp(entry_time_str)
        return abs((entry_time - target_time).total_seconds()) <= 1
    except Exception:
        return False

def load_eve_quic_entries(eve_path):
    entries = []
    with open(eve_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("event_type") == "quic":
                    entries.append(entry)
            except json.JSONDecodeError:
                continue
    return entries

def main():
    if len(sys.argv) != 5:
        print("Usage: python compare_custom_to_eve.py <custom_log.jsonl> <eve.json> <found_output.jsonl> <not_found_output.jsonl>")
        sys.exit(1)

    custom_path = sys.argv[1]
    eve_path = sys.argv[2]
    found_path = sys.argv[3]
    not_found_path = sys.argv[4]

    print(f"📥 Loading Suricata QUIC entries from {eve_path}...")
    eve_quic = load_eve_quic_entries(eve_path)
    print(f"✅ Loaded {len(eve_quic)} QUIC entries from Suricata")

    found, not_found = [], []

    with open(custom_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                timestamp = entry.get("timestamp")
                src_port = entry.get("src_port")
                domain = entry.get("domain", "unknown")
                mutation = entry.get("mutation_id", "unknown")

                if not timestamp or not src_port:
                    continue

                try:
                    target_time = parse_timestamp(timestamp)
                except Exception as e:
                    print(f"[!] Invalid timestamp in entry: {timestamp}")
                    continue

                matched = False
                for eve_entry in eve_quic:
                    if "timestamp" in eve_entry and src_port_match(eve_entry, src_port):
                        if timestamp_match(eve_entry["timestamp"], target_time):
                            # Add metadata
                            eve_entry["domain"] = domain
                            eve_entry["mutation_id"] = mutation
                            found.append(eve_entry)
                            matched = True
                            break

                if not matched:
                    not_found.append({
                        "timestamp": timestamp,
                        "src_port": src_port,
                        "domain": domain,
                        "mutation_id": mutation
                    })

            except json.JSONDecodeError:
                print(f"[!] Skipping invalid JSON: {line}")
                continue

    # Write results
    with open(found_path, 'w') as fout:
        for match in found:
            fout.write(json.dumps(match) + "\n")

    with open(not_found_path, 'w') as fnout:
        for miss in not_found:
            fnout.write(json.dumps(miss) + "\n")

    print(f"\n✅ Done. Matches: {len(found)}, Not found: {len(not_found)}")
    print(f"📄 Output written to:\n  Matches: {found_path}\n  Not found: {not_found_path}")

if __name__ == "__main__":
    main()
