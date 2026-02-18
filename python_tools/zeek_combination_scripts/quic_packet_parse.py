import sys

def parse_quic_header(hex_str):
    try:
        data = bytes.fromhex(hex_str)
        index = 0

        # First byte: flags
        flags = data[index]
        index += 1

        is_long_header = (flags & 0x80) != 0
        header = {
            "flags": f"{flags:02x}",
            "is_long_header": is_long_header
        }

        if is_long_header:
            # QUIC long header format
            version = data[index:index+4].hex()
            index += 4
            header["version"] = version

            dcid_len = data[index]
            index += 1
            dcid = data[index:index+dcid_len].hex()
            index += dcid_len
            header["dcid_length"] = dcid_len
            header["dcid"] = dcid

            scid_len = data[index]
            index += 1
            scid = data[index:index+scid_len].hex()
            index += scid_len
            header["scid_length"] = scid_len
            header["scid"] = scid

            # Packet type is encoded in high 2 bits of flags byte
            packet_type = (flags & 0x30) >> 4
            type_map = {
                0x0: "Initial",
                0x1: "0-RTT",
                0x2: "Handshake",
                0x3: "Retry"
            }
            header["packet_type"] = type_map.get(packet_type, "Unknown")

            # Packet number length (last 2 bits + 1)
            pn_len = (flags & 0x03) + 1
            header["pn_length"] = pn_len
        else:
            # QUIC short header (not handled fully here)
            header["version"] = None
            header["packet_type"] = "1-RTT (Short)"
            header["pn_length"] = (flags & 0x03) + 1
            header["dcid"] = data[index:].hex()

        header["remaining_payload"] = data[index:].hex()
        return header

    except Exception as e:
        print(f"[ERROR] Failed to parse QUIC header: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_quic_header.py <hex_string>")
        sys.exit(1)

    hex_input = sys.argv[1]
    header = parse_quic_header(hex_input)
    if header:
        for k, v in header.items():
            print(f"{k}: {v}")
