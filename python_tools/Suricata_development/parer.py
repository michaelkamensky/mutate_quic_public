import json
import sys

def extract_timestamps_and_ports(log_path):
    with open(log_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                timestamp = entry.get("timestamp")
                src_port = entry.get("src_port")
                print(f"{timestamp}\t{src_port}")
            except json.JSONDecodeError:
                print(f"[!] Skipping invalid JSON: {line}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_times_ports.py <log_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    extract_timestamps_and_ports(log_file)