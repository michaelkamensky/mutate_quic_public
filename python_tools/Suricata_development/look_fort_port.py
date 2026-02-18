import sys
import json
from datetime import datetime

def src_port_match(entry, port):
    """Check only source port fields"""
    src_keys = ['src_port', 'sport', 'id.orig_p']

    for key in src_keys:
        if key in entry and str(entry[key]) == str(port):
            return True

    # Check nested objects
    for k, v in entry.items():
        if isinstance(v, dict):
            for subk, subv in v.items():
                if subk in src_keys and str(subv) == str(port):
                    return True
    return False

def timestamp_match(entry_time_str, target_time):
    try:
        if entry_time_str.endswith("Z"):
            entry_time = datetime.strptime(entry_time_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            entry_time = datetime.strptime(entry_time_str, "%Y-%m-%dT%H:%M:%S.%f%z").replace(tzinfo=None)
    except ValueError:
        try:
            entry_time = datetime.strptime(entry_time_str, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            try:
                entry_time = datetime.strptime(entry_time_str, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                return False

    delta = abs((entry_time - target_time).total_seconds())
    return delta <= 1

def main():
    if len(sys.argv) != 4:
        print("Usage: python look_for_src_port.py <eve.json> <src_port> <timestamp>")
        print("Timestamp format: YYYY-MM-DDTHH:MM:SS[.ffffff]")
        return

    filename = sys.argv[1]
    target_port = sys.argv[2]

    try:
        try:
            target_time = datetime.strptime(sys.argv[3], "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            target_time = datetime.strptime(sys.argv[3], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        print("❌ Invalid timestamp format. Use: YYYY-MM-DDTHH:MM:SS[.ffffff]")
        return

    print(f"🔍 Looking for event_type='quic', source port={target_port}, timestamp ±1s of {target_time}...\n")

    matches = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("event_type") != "quic":
                    continue
                if "timestamp" in entry and src_port_match(entry, target_port):
                    if timestamp_match(entry["timestamp"], target_time):
                        matches.append(entry)
            except json.JSONDecodeError:
                continue

    if matches:
        print(f"✅ Found {len(matches)} matching entries:\n")
        for match in matches:
            print(json.dumps(match, indent=2))
    else:
        print(f"❌ No matching entries found.")

if __name__ == "__main__":
    main()
