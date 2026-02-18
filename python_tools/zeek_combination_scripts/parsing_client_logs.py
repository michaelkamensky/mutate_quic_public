import json
import sys

def extract_packets(input_file, output_file):
    extracted = []

    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                original = entry.get("original")
                mutated = entry.get("mutated")

                if original and mutated:
                    extracted.append({
                        "original": original,
                        "mutated": mutated
                    })

            except json.JSONDecodeError as e:
                print(f"[!] Skipping invalid JSON line: {e}")

    with open(output_file, 'w') as f:
        json.dump(extracted, f, indent=2)

    print(f"[✓] Extracted {len(extracted)} packet pairs to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract_packets.py <input.json> <output.json>")
        sys.exit(1)

    extract_packets(sys.argv[1], sys.argv[2])
