import json
import argparse
import os

def check_quic_packets(eve_file_path):
    if not os.path.isfile(eve_file_path):
        print(f"Error: File '{eve_file_path}' does not exist.")
        return

    quic_found = False
    line_count = 0
    quic_lines = []

    with open(eve_file_path, 'r') as f:
        for line in f:
            line_count += 1
            try:
                event = json.loads(line)
                if event.get('proto') == 'UDP' and 'quic' in event.get('app_proto', '').lower():
                    quic_found = True
                    quic_lines.append(event)
                    print(f"[QUIC] Line {line_count}: {json.dumps(event, indent=2)}")
            except json.JSONDecodeError:
                print(f"Error decoding JSON on line {line_count}")
                continue

    if not quic_found:
        print("No QUIC packets found in the file.")
    else:
        print(f"\nTotal QUIC packets found: {len(quic_lines)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan Suricata eve.json for QUIC packets.")
    parser.add_argument("filepath", help="Path to Suricata eve.json file")
    args = parser.parse_args()

    check_quic_packets(args.filepath)