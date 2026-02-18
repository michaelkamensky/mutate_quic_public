import csv
import json
import sys

def extract_zeek_quic_to_json(zeek_log_path, output_json_path):
    entries = []

    with open(zeek_log_path, 'r') as f:
        reader = csv.reader(f, delimiter='\t')
        field_names = None

        for row in reader:
            if not row:
                continue

            # Header row
            if row[0].startswith("#fields"):
                field_names = row[1:]  # Skip the "#fields"
                continue

            # Skip other comments or metadata
            if row[0].startswith("#") or not field_names:
                continue

            # Normal row
            entry = dict(zip(field_names, row))
            entries.append(entry)

    # Write as JSON lines
    with open(output_json_path, 'w') as out_f:
        for entry in entries:
            json.dump(entry, out_f)
            out_f.write('\n')

    print(f"[✓] Parsed {len(entries)} entries to {output_json_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract_quic.py zeek_quic.log zeek_quic_parsed.json")
    else:
        extract_zeek_quic_to_json(sys.argv[1], sys.argv[2])