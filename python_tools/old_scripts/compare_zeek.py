import json
import csv

def load_json(file_path):
    with open(file_path, 'r') as f:
        return [json.loads(line.strip()) for line in f if line.strip()]

def load_zeek_quic_dcids(file_path):
    dcids = set()
    with open(file_path, 'r') as f:
        reader = csv.reader(f, delimiter='\t')
        header = None

        for row in reader:
            if not row:
                continue
            if row[0].startswith("#fields"):
                header = row
                continue
            if row[0].startswith("#") or header is None:
                continue

            try:
                row_dict = dict(zip(header, row))
                dcid = row_dict.get("client_initial_dcid", "")
                if dcid:
                    dcids.add(dcid)
            except Exception as e:
                print(f"[ERROR] Failed to parse row: {row} — {e}")

    return dcids

def compare_packets(zeek_path, packet_path):
    zeek_dcids = load_zeek_quic_dcids(zeek_path)
    print(f"[DEBUG] Loaded {len(zeek_dcids)} DCIDs from Zeek")

    packet_data = load_json(packet_path)
    not_seen = []

    for entry in packet_data:
        mutated_hex = entry.get("mutated", "")
        if len(mutated_hex) < 20:
            continue  # Too short to contain DCID

        try:
            dcid_len = int(mutated_hex[2:4], 16)
            dcid = mutated_hex[4:4 + dcid_len * 2]
        except:
            continue

        if dcid not in zeek_dcids:
            print(f"[MISS]  DCID {dcid} NOT found in Zeek ❌")
            not_seen.append(entry)
        else:
            print(f"[HIT]   DCID {dcid} FOUND in Zeek ✅")

    print(f"\nSummary: {len(not_seen)} of {len(packet_data)} packets not seen in Zeek")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python compare_suricate.py zeek_quic.log mutated_packets.json")
    else:
        compare_packets(sys.argv[1], sys.argv[2])
