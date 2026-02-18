import json
import sys
from datetime import datetime

# ---- PART 1: Extract client packets ----
def extract_packets(client_input_path):
    packets = []
    with open(client_input_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                packets.append(entry)
            except json.JSONDecodeError:
                continue
    return packets

# ---- PART 2: Parse eve.json QUIC entries ----
def parse_eve_log(eve_path):
    quic_entries = []
    with open(eve_path, 'r') as f:
        for line in f:
            try:
                obj = json.loads(line)
                if obj.get("event_type") == "quic":
                    quic_entries.append(obj)
            except json.JSONDecodeError:
                continue
    return quic_entries

# ---- PART 3: Parse output.json logs with mutated + response ----
def parse_output_log(output_path):
    results_by_timestamp = {}
    results_by_dcid = {}

    def extract_dcid(packet_hex):
        try:
            data = bytes.fromhex(packet_hex)
            if len(data) < 7:
                return None
            dcid_len = data[5]
            return data[6:6 + dcid_len].hex()
        except Exception:
            return None

    with open(output_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                ts = entry.get("timestamp")
                dcid = entry.get("dcid") or ""

                # Try to extract dcid from mutated or original if missing
                if not dcid:
                    pkt = entry.get("mutated") or entry.get("original")
                    if pkt:
                        dcid = extract_dcid(pkt)
                        if dcid:
                            entry["dcid"] = dcid  # inject it for consistency

                if ts:
                    results_by_timestamp[ts] = entry
                if dcid:
                    results_by_dcid[dcid] = entry
            except json.JSONDecodeError:
                continue

    return results_by_timestamp, results_by_dcid

# ---- PART 4: Parse timestamp ----
def parse_timestamp(ts_str):
    ts_str = ts_str.rstrip('Z').split('+')[0]
    if '.' in ts_str:
        prefix, frac = ts_str.split('.')
        frac = (frac + "000000")[:6]
        ts_str = f"{prefix}.{frac}"
    try:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")

# ---- PART 5: Match by source port ----
def src_port_match(entry, port):
    src_keys = ['src_port', 'sport', 'id.orig_p']
    for key in src_keys:
        if key in entry and str(entry[key]) == str(port):
            return True
    for _, v in entry.items():
        if isinstance(v, dict):
            for subk, subv in v.items():
                if subk in src_keys and str(subv) == str(port):
                    return True
    return False

# ---- PART 6: Compare timestamps ----
def timestamp_match(entry_time_str, target_time):
    try:
        entry_time = parse_timestamp(entry_time_str)
        return abs((entry_time - target_time).total_seconds()) <= 1
    except Exception:
        return False

# ---- PART 7: QUIC header parser ----
def parse_quic_header(hex_str):
    try:
        data = bytes.fromhex(hex_str)
        index = 0
        flags = data[index]
        index += 1
        is_long_header = (flags & 0x80) != 0
        header = {
            "flags": f"{flags:02x}",
            "is_long_header": is_long_header
        }
        if is_long_header:
            version = data[index:index+4].hex()
            index += 4
            dcid_len = data[index]
            index += 1
            dcid = data[index:index+dcid_len].hex()
            index += dcid_len
            scid_len = data[index]
            index += 1
            scid = data[index:index+scid_len].hex()
            index += scid_len
            header.update({
                "version": version,
                "dcid_length": dcid_len,
                "dcid": dcid,
                "scid_length": scid_len,
                "scid": scid,
                "packet_type": {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}.get((flags & 0x30) >> 4, "Unknown"),
                "pn_length": (flags & 0x03) + 1
            })
        else:
            header.update({
                "version": None,
                "packet_type": "1-RTT (Short)",
                "pn_length": (flags & 0x03) + 1,
                "dcid": data[index:].hex()
            })
        header["remaining_payload"] = data[index:].hex()
        return header
    except Exception:
        return None

# ---- PART 8: Main logic ----
def main(client_path, eve_path, output_path, found_path, not_found_path, responded_missing_path, responded_matched_path):
    print("[*] Loading client packets...")
    packets = extract_packets(client_path)

    print("[*] Parsing eve.json entries...")
    eve_entries = parse_eve_log(eve_path)

    print("[*] Parsing output.json responses...")
    output_by_ts, output_by_dcid = parse_output_log(output_path)

    found = []
    not_found = []
    responded_missing = []
    responded_matched = []

    for entry in packets:
        timestamp = entry.get("timestamp")
        src_port = entry.get("src_port")
        domain = entry.get("domain", "unknown")
        mutation = entry.get("mutation_id", "unknown")
        dcid = entry.get("dcid", "")
        scid = ""

        if not timestamp or not src_port:
            continue

        try:
            target_time = parse_timestamp(timestamp)
        except Exception as e:
            print(f"[DEBUG] Invalid timestamp format: {timestamp} — {e}")
            continue

        # Lookup response from output.json
        output_entry = output_by_ts.get(timestamp)

        if not output_entry and dcid:
            dcid_lower = dcid.lower()
            for k, v in output_by_dcid.items():
                if k.lower() == dcid_lower:
                    output_entry = v
                    print(f"[DEBUG] ✅ Found output.json match by DCID: {dcid}")
                    break

        if not output_entry:
            print(f"[DEBUG] ❌ No output.json match for entry:")
            print(f"         timestamp: {timestamp}")
            print(f"         dcid     : {dcid}")
        if not output_entry and dcid:
            output_entry = output_by_dcid.get(dcid)

        if not output_entry:
            print(f"[DEBUG] ❌ No output.json match for entry:")
            print(f"         timestamp: {timestamp}")
            print(f"         dcid     : {dcid}")
        else:
            print(f"[DEBUG] ✅ Found output.json match:")
            print(f"         timestamp: {timestamp}")
            print(f"         dcid     : {dcid}")

        packet = output_entry.get("mutated") if output_entry else ""
        response = output_entry.get("response") if output_entry else ""
        response_header = parse_quic_header(response) if response else None

        matched_entry = None
        if dcid:
            dcid_lower = dcid.lower()
            for eve_entry in eve_entries:
                quic_info = eve_entry.get("quic", {})
                eve_dcid = quic_info.get("dcid", "").lower()
                if eve_dcid == dcid_lower:
                    matched_entry = eve_entry
                    print(f"[DEBUG] ✅ Suricata match for DCID {dcid_lower}")
                    break

        if not matched_entry:
            print(f"[DEBUG] ❌ No Suricata match for DCID {dcid.lower()} @ {timestamp}")


        base = {
            "mutation_id": mutation,
            "domain": domain,
            "timestamp": timestamp,
            "source": "mutated",
            "dcid": dcid,
            "scid": scid,
            "matched_field": "src_port"
        }

        if packet:
            base["packet"] = packet
        if response:
            base["response"] = response
        if response_header:
            base["response_header"] = response_header

        if matched_entry:
            base["suricata_entry"] = matched_entry
            responded_matched.append(base)
            found.append(base)
        else:
            base["suricata_entry"] = None
            responded_missing.append(base)
            not_found.append(base)

    with open(found_path, 'w') as f:
        json.dump(found, f, indent=2)
    with open(not_found_path, 'w') as f:
        json.dump(not_found, f, indent=2)
    with open(responded_missing_path, 'w') as f:
        json.dump(responded_missing, f, indent=2)
    with open(responded_matched_path, 'w') as f:
        json.dump(responded_matched, f, indent=2)

    print(f"[✓] Matched: {len(found)} | Unmatched: {len(not_found)}")

if __name__ == "__main__":
    if len(sys.argv) != 8:
        print("Usage: python combined_suricata_parser.py <client_input.json> <eve.json> <output.json> <found.json> <not_found.json> <responded_missing.json> <responded_matched.json>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])
