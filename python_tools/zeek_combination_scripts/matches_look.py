import json
import sys

def find_id_in_zeek(search_id, json_path):
    search_id = search_id.lower()
    matches = []

    with open(json_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                entry = json.loads(line.strip())
                for field in ["client_initial_dcid", "client_scid", "server_scid"]:
                    value = entry.get(field, "").lower()
                    if value != "-" and value == search_id:
                        matches.append({
                            "line": line_num,
                            "field": field,
                            "entry": entry
                        })
            except json.JSONDecodeError:
                continue

    if matches:
        print(f"[✓] Found {len(matches)} match(es) for ID '{search_id}':")
        for match in matches:
            print(f"  • Line {match['line']} — field: {match['field']}")
            print(f"    {json.dumps(match['entry'], indent=4)}\n")
    else:
        print(f"[✗] No match found for ID '{search_id}'")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python match_id.py <dcid_or_scid> <zeek_quic_parsed.json>")
    else:
        find_id_in_zeek(sys.argv[1], sys.argv[2])
