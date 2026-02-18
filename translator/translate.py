import sys

def parse_quic_initial_packet(hex_str):
    data = bytes.fromhex(hex_str)
    ptr = 0

    # First byte: flags
    flags = data[ptr]
    ptr += 1

    long_header = (flags & 0x80) != 0
    packet_type = (flags & 0x30) >> 4
    packet_type_str = {
        0x0: "Initial",
        0x1: "0-RTT",
        0x2: "Handshake",
        0x3: "Retry"
    }.get(packet_type, "Unknown")

    print(f"Flags: 0x{flags:02x}")
    print(f"  Long Header: {long_header}")
    print(f"  Packet Type: {packet_type_str}")

    # Version (4 bytes)
    version = int.from_bytes(data[ptr:ptr+4], "big")
    print(f"Version: 0x{version:08x}")
    ptr += 4

    # DCID length
    dcid_len = data[ptr]
    ptr += 1
    dcid = data[ptr:ptr+dcid_len]
    ptr += dcid_len
    print(f"DCID Length: {dcid_len}")
    print(f"DCID: {dcid.hex()}")

    # SCID length
    scid_len = data[ptr]
    ptr += 1
    scid = data[ptr:ptr+scid_len]
    ptr += scid_len
    print(f"SCID Length: {scid_len}")
    print(f"SCID: {scid.hex()}")

    # Remaining = Token + Length + Packet Number + Encrypted Payload
    print(f"Remaining Payload (hex): {data[ptr:].hex()}")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <quic_packet_hex>")
        sys.exit(1)

    hex_input = sys.argv[1]
    try:
        parse_quic_initial_packet(hex_input)
    except Exception as e:
        print(f"Error parsing packet: {e}")

if __name__ == "__main__":
    main()
