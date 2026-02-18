import json
import socket
import binascii
import sys
import time

def send_quic_packets(json_file, total_sends=3, delay_between_packets=0.5, delay_between_rounds=2.0):
    try:
        with open(json_file, "r") as f:
            entries = json.load(f)
    except Exception as e:
        print(f"[!] Failed to load JSON: {e}")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Resolve all domains once
    resolved_ips = {}
    for entry in entries:
        domain = entry["domain"]
        if domain not in resolved_ips:
            try:
                resolved_ips[domain] = socket.gethostbyname(domain)
            except Exception as e:
                print(f"[!] Failed to resolve {domain}: {e}")
                resolved_ips[domain] = None

    for round_num in range(total_sends):
        print(f"\n=== Sending Round {round_num + 1}/{total_sends} ===")
        for i, entry in enumerate(entries):
            domain = entry["domain"]
            ip = resolved_ips.get(domain)
            if not ip:
                continue

            try:
                packet_bytes = binascii.unhexlify(entry["packet"])
                sock.sendto(packet_bytes, (ip, 443))
                print(f"[+] Sent packet {i+1} to {domain} ({ip})")
                time.sleep(delay_between_packets)  # Delay after each packet
            except Exception as e:
                print(f"[!] Failed to send packet {i+1} to {domain}: {e}")
        if round_num < total_sends - 1:
            print(f"[*] Waiting {delay_between_rounds} seconds before next round...")
            time.sleep(delay_between_rounds)  # Delay after each round

    sock.close()
    print("\n[+] Finished sending all packets 3 times.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python send_quic_packets.py path_to_json")
    else:
        send_quic_packets(
            json_file=sys.argv[1],
            total_sends=3,
            delay_between_packets=0.5,     # seconds between each packet
            delay_between_rounds=2.0       # seconds between rounds
        )
