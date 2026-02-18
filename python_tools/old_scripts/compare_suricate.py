import json
import binascii
from difflib import SequenceMatcher
from collections import defaultdict

def load_json_lines(file_path):
    with open(file_path, 'r') as f:
        return [json.loads(line.strip()) for line in f if line.strip()]

def load_suricata_quic(file_path):
    return [json.loads(line) for line in open(file_path) if '"event_type":"quic"' in line]

def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

def parse_quic_header(packet_hex):
    try:
        raw = binascii.unhexlify(packet_hex)
        first_byte = raw[0]
        long_header = (first_byte & 0x80) != 0

        if long_header:
            version_bytes = raw[1:5]
            version = int.from_bytes(version_bytes, byteorder='big')
            dcid_len = raw[5]
            dcid = raw[6:6+dcid_len]
            scid_len = raw[6+dcid_len]
            scid_start = 7 + dcid_len
            scid = raw[scid_start:scid_start+scid_len]

            parsed = {
                "version": str(version),
                "dcid": dcid.hex(),
                "scid": scid.hex()
            }

            print(f"\n[DEBUG] Parsed QUIC Header from hex:")
            print(f"  Raw hex: {packet_hex[:100]}...")
            print(f"  Version: {version} (bytes: {version_bytes.hex()})")
            print(f"  DCID ({dcid_len} bytes): {parsed['dcid']}")
            print(f"  SCID ({scid_len} bytes): {parsed['scid']}")
            print(f"  Signature: {parsed['version']}:{parsed['dcid']}:{parsed['scid']}")

            return parsed
        else:
            print(f"[DEBUG] Short header detected (not parsed): {packet_hex[:80]}...")
            return None
    except Exception as e:
        print(f"[!] Error parsing QUIC header from hex: {packet_hex[:80]}... -> {e}")
        return None

def compare_packets(eve_path, packet_path):
    eve_entries = load_suricata_quic(eve_path)
    packet_data = load_json_lines(packet_path)
    total_packets = len(packet_data)

    # Suricata signatures (version:dcid:scid)
    seen_quic_signatures = set()
    for eve in eve_entries:
        q = eve.get("quic", {})
        key = f'{q.get("version")}:{q.get("dcid")}:{q.get("scid")}'
        seen_quic_signatures.add(key)

    not_seen = []
    diffs = []
    unseen_counts = defaultdict(int)
    diff_counts = defaultdict(int)

    for entry in packet_data:
        mutated_hex = entry.get("mutated")
        orig_hex = entry.get("original")
        mutated_resp = entry.get("response", "")
        orig_resp = entry.get("original_response", "")
        mutation_id = entry.get("mutation_id")
        domain = entry.get("domain")

        sig = parse_quic_header(mutated_hex)
        if not sig:
            not_seen.append({
                "mutation_id": mutation_id,
                "domain": domain,
                "error": "Could not parse QUIC header",
                "mutated": mutated_hex
            })
            unseen_counts[mutation_id] += 1
            continue

        key = f'{sig["version"]}:{sig["dcid"]}:{sig["scid"]}'
        print(f"[DEBUG] Generated signature key: {key}")

        # Optional: Check if it was seen
        if key not in seen_quic_signatures:
            print("[DEBUG] This key was NOT found in Suricata eve.json entries.\n")
        else:
            print("[DEBUG] This key was found in Suricata eve.json entries.\n")

            # Prepare summary for not_seen
            unseen_summary = {
                "total_mutated_packets": total_packets,
                "total_unseen": len(not_seen),
                "mutation_counts": []
            }
            for mid, count in sorted(unseen_counts.items(), key=lambda x: x[1], reverse=True):
                unseen_summary["mutation_counts"].append({
                    "mutation_id": mid,
                    "count": count,
                    "percentage": round(100.0 * count / total_packets, 2)
                })

    # Prepare summary for diffs
    diff_summary = {
        "total_mutated_packets": total_packets,
        "total_different_responses": len(diffs),
        "mutation_counts": []
    }
    for mid, count in sorted(diff_counts.items(), key=lambda x: x[1], reverse=True):
        diff_summary["mutation_counts"].append({
            "mutation_id": mid,
            "count": count,
            "percentage": round(100.0 * count / total_packets, 2)
        })

    # Save mutations not seen
    with open("mutations_not_seen.json", "w") as f:
        json.dump({
            "not_seen": not_seen,
            "summary": unseen_summary
        }, f, indent=2)

    # Save response diff report
    with open("response_diff_report.json", "w") as f:
        json.dump({
            "response_differences": diffs,
            "summary": diff_summary
        }, f, indent=2)

    print("Wrote mutations_not_seen.json and response_diff_report.json")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python compare_quic.py <eve.json> <packet_data.json>")
        exit(1)
    compare_packets(sys.argv[1], sys.argv[2])

