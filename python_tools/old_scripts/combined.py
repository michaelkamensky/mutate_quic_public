import json
import sys
from datetime import datetime, timedelta

def parse_time(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "").replace("+0000", "+00:00"))
    except Exception:
        return None

def load_eve_logs(eve_path):
    eve_entries = []
    with open(eve_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                if entry.get("event_type") == "quic":
                    ts = parse_time(entry.get("timestamp", ""))
                    entry["_parsed_ts"] = ts
                    eve_entries.append(entry)
            except Exception as e:
                print(f"[EVE] JSON parse error: {e}")
    return eve_entries

def match_entry(custom_entry, eve_entries, time_window=1.0):
    match_candidates = []
    ts1 = parse_time(custom_entry.get("timestamp"))
    if not ts1:
        return None

    target_ip = custom_entry.get("ip")
    target_port = custom_entry.get("port")
    src_port = custom_entry.get("src_port")

    for eve in eve_entries:
        ts2 = eve.get("_parsed_ts")
        if not ts2 or abs((ts1 - ts2).total_seconds()) > time_window:
            continue

        # Match direction A→B or B→A
        c_src = (custom_entry.get("src_ip", "172.26.12.158"), src_port)
        c_dst = (target_ip, target_port)

        e1 = (eve.get("src_ip"), eve.get("src_port"))
        e2 = (eve.get("dest_ip"), eve.get("dest_port"))

        if (c_src == e1 and c_dst == e2) or (c_src == e2 and c_dst == e1):
            match_candidates.append(eve)

    return match_candidates[0] if match_candidates else None

def cross_match(custom_path, eve_path):
    eve_entries = load_eve_logs(eve_path)
    matched, unmatched = [], []

    with open(custom_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                match = match_entry(entry, eve_entries)
                if match:
                    matched.append({"custom": entry, "eve": match})
                else:
                    unmatched.append(entry)
            except Exception as e:
                print(f"[Custom] JSON parse error: {e}")

    with open("matched_packets.jsonl", "w") as f:
        for pair in matched:
            f.write(json.dumps(pair) + "\n")

    with open("unmatched_packets.jsonl", "w") as f:
        for entry in unmatched:
            f.write(json.dumps(entry) + "\n")

    print(f"✅ Done. Matches: {len(matched)}, Misses: {len(unmatched)}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python cross_match_logs.py output_suricata.json eve.json")
        sys.exit(1)

    cross_match(sys.argv[1], sys.argv[2])