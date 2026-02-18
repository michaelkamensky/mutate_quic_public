import json

def read_custom_log(file_path):
    with open(file_path, 'r') as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                print(f"[Entry {line_number}]")
                print(json.dumps(entry, indent=4))
            except json.JSONDecodeError as e:
                print(f"[Error at line {line_number}]: {e}")

if __name__ == "__main__":
    read_custom_log("output_suricata.json")
