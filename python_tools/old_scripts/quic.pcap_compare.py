import json
import binascii
from scapy.all import rdpcap, UDP, Raw

def load_json_packets(json_path):
    with open(json_path, 'r') as f:
        lines = f.readlines()
    packets = [json.loads(line.strip()) for line in lines if line.strip()]
    return packets

def extract_quic_payloads_from_pcap(pcap_path):
    packets = rdpcap(pcap_path)
    udp_payloads = []

    for pkt in packets:
        if UDP in pkt and Raw in pkt:
            udp_payloads.append(bytes(pkt[Raw]))

    return udp_payloads

def generate_report(json_packets, udp_payloads):
    seen_mutated = set()
    seen_responses = set()
    report = []

    for entry in json_packets:
        original = entry.get("original", "")
        mutated = entry.get("mutated", "")
        original_resp = entry.get("original_response", "")
        mutated_resp = entry.get("response", "")
        domain = entry.get("domain")
        mutation_id = entry.get("mutation_id")

        mutated_bytes = binascii.unhexlify(mutated)
        mutated_seen = mutated_bytes in udp_payloads

        mutated_resp_bytes = binascii.unhexlify(mutated_resp) if mutated_resp else None
        response_seen = mutated_resp_bytes in udp_payloads if mutated_resp_bytes else False

        entry_result = {
            "mutation_id": mutation_id,
            "domain": domain,
            "mutated_seen": mutated_seen,
            "response_seen": response_seen,
            "response_matches_original": mutated_resp == original_resp,
        }

        if not mutated_seen:
            entry_result["note"] = "❌ Mutated packet not seen in PCAP"
        elif not response_seen:
            entry_result["note"] = "⚠️ Mutated packet seen but no server response in PCAP"
        elif mutated_resp != original_resp:
            entry_result["note"] = "⚠️ Response to mutated differs from original"
        else:
            entry_result["note"] = "✅ Mutated + response match original"

        report.append(entry_result)

    return report

def print_report(report):
    print("\n=== QUIC Mutation PCAP Report ===\n")
    for r in report:
        print(f"Mutation {r['mutation_id']} ({r['domain']})")
        print(f"  - Mutated Seen: {r['mutated_seen']}")
        print(f"  - Response Seen: {r['response_seen']}")
        print(f"  - Response Matches Original: {r['response_matches_original']}")
        print(f"  - Note: {r['note']}")
        print("")

if __name__ == "__main__":
    JSON_PATH = "output.json"
    PCAP_PATH = "quic.pcap"

    json_packets = load_json_packets(JSON_PATH)
    udp_payloads = extract_quic_payloads_from_pcap(PCAP_PATH)
    report = generate_report(json_packets, udp_payloads)
    print_report(report)