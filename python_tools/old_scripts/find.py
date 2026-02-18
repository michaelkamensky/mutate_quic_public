import json
import sys

def find_entries(eve_file, port, timestamp_prefix):
    with open(eve_file, 'r') as f:
        for i, line in enumerate(f, 1):
            try:
                entry = json.loads(line.strip())
                # Match dest port and timestamp prefix
                if (
                    str(entry.get("dest_port", "")) == str(port)
                    and entry.get("timestamp", "").startswith(timestamp_prefix)
                ):
                    print(f"\n[Match at line {i}]:")
                    print(json.dumps(entry, indent=4))
            except json.JSONDecodeError as e:
                print(f"[Error parsing line {i}]: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python find_eve_instance.py <eve.json> <port> <timestamp_prefix>")
        sys.exit(1)

    file_path = sys.argv[1]
    port = sys.argv[2]
    timestamp_prefix = sys.argv[3]

    find_entries(file_path, port, timestamp_prefix)
