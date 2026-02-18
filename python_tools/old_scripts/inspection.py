import re
import hashlib
import sys
import traceback
from collections import defaultdict
from binascii import unhexlify

from cryptography.hazmat.primitives import hashes
from aioquic.quic.crypto import CryptoPair
from aioquic.tls import Buffer, hkdf_extract
from aioquic.quic.packet import (
    pull_quic_header,
    PACKET_TYPE_INITIAL,
    QuicFrameType
)
from aioquic.tls import CipherSuite


INITIAL_SALT = {
    0x00000001: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),  # draft-29
    0x1: bytes.fromhex("ef4fb0abb4744785632a4e1d8c57f0e7b27e3e9c"),      # RFC 9000
}


def decode_quic_packet_type(first_byte):
    if first_byte & 0x80:
        type_bits = (first_byte & 0x30) >> 4
        return {
            0x0: "Initial",
            0x1: "0-RTT",
            0x2: "Handshake",
            0x3: "Retry"
        }.get(type_bits, "Unknown")
    else:
        return "Short Header"


def hkdf_label(label: str, length: int) -> bytes:
    label_bytes = f"quic {label}".encode()
    return (
        length.to_bytes(2, "big") +
        bytes([len(label_bytes)]) +
        label_bytes +
        bytes([0])  # empty context
    )

def get_initial_secret(version: int, dcid: bytes) -> bytes:
    if version == 0x1:
        salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    elif version == 0x00000001:
        salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")  # fallback for draft-29
    else:
        raise ValueError(f"No salt for version {version:#x}")
    return hkdf_extract(hashes.SHA256(), salt, dcid)


def read_varint_with_len(buf: bytes, offset: int):
    if offset >= len(buf):
        raise ValueError("Offset out of range")
    first_byte = buf[offset]
    prefix = first_byte >> 6
    length = 1 << prefix  # 1, 2, 4, or 8 bytes

    if offset + length > len(buf):
        raise ValueError("Incomplete varint")

    value = int.from_bytes(buf[offset:offset + length], "big") & ((1 << (8 * length - 2)) - 1)
    return value, length


def decrypt_initial_payload(hex_string):

    data = unhexlify(hex_string)
    buf = Buffer(data=data)

    try:
        header = pull_quic_header(buf, host_cid_length=8)
    except Exception as e:
        return None, f"Header parse failed: {e}"

    if header.packet_type != PACKET_TYPE_INITIAL:
        return None, "Not an Initial packet"

    version = header.version
    dcid = header.destination_cid

    try:
        initial_secret = get_initial_secret(version, dcid)
    except Exception as e:
        return None, str(e)

    crypto = CryptoPair()
    crypto.cipher_suite = CipherSuite.AES_128_GCM_SHA256
    crypto.setup_initial(initial_secret, False, version)

    try:
        # === Reconstruct header offset manually ===
        ptr = 1 + 4  # First byte + Version

        dcid_len = data[ptr]
        ptr += 1 + dcid_len

        scid_len = data[ptr]
        ptr += 1 + scid_len

        # Read token length (varint)
        token_len, token_len_len = read_varint_with_len(data, ptr)
        ptr += token_len_len + token_len

        # Read length field (varint)
        _, length_len = read_varint_with_len(data, ptr)
        header_end = ptr
        ptr += length_len

        # Read packet number bytes
        pn_len = (data[0] & 0x03) + 1
        packet_number = int.from_bytes(data[ptr:ptr + pn_len], byteorder="big")

        header_bytes = data[:header_end]
        encrypted_payload = data[ptr + pn_len:]

        # Decrypt
        # Packet number as int
        packet_number = int.from_bytes(data[ptr:ptr + pn_len], byteorder="big")

        # Reconstruct full packet
        full_packet = header_bytes + data[ptr:ptr + pn_len] + encrypted_payload

        # Call with correct args
        plain_header, decrypted, _, = crypto.decrypt_packet(
            full_packet,
            len(header_bytes),
            packet_number
        )


    except Exception as e:
        print("=== Full traceback ===")
        traceback.print_exc()
        print("======================")
        return None, f"Decryption failed: {type(e).__name__}: {e}"

    # === Parse decrypted payload frames ===
    frames = []
    frame_buf = Buffer(data=decrypted)

    try:
        while not frame_buf.eof():
            start_pos = frame_buf.tell()
            try:
                frame_type = frame_buf.pull_varint()
                if frame_type == QuicFrameType.CRYPTO:
                    offset = frame_buf.pull_varint()
                    length = frame_buf.pull_varint()

                    if frame_buf.tell() + length > len(decrypted):
                        raise ValueError(f"Length {length} goes past buffer (pos={frame_buf.tell()}, size={len(decrypted)})")

                    crypto_data = frame_buf.pull_bytes(length)
                    frames.append({
                        "frame": "CRYPTO",
                        "offset": offset,
                        "length": length,
                        "data": crypto_data.hex()
                    })
                else:
                    frames.append({"frame": f"OTHER({frame_type})"})
            except Exception as inner_e:
                frames.append({
                    "frame": "ParseError",
                    "start": start_pos,
                    "error": f"{type(inner_e).__name__}: {inner_e}"
                })
                break
    except Exception as e:
        return None, f"Fatal frame loop error: {type(e).__name__}: {e}"

    return frames, None


def parse_quic_long_header(hex_string):
    bytes_data = bytes.fromhex(hex_string)
    parsed = {}

    if len(bytes_data) < 6:
        parsed["error"] = "Packet too short"
        return parsed

    first_byte = bytes_data[0]
    parsed["First Byte"] = f"0x{first_byte:02x}"
    parsed["Header Form"] = "Long Header" if first_byte & 0x80 else "Short Header"
    parsed["Packet Type"] = decode_quic_packet_type(first_byte)

    if not first_byte & 0x80:
        parsed["Note"] = "Short header parsing not implemented in detail"
        return parsed

    version = bytes_data[1:5]
    parsed["Version"] = f"0x{version.hex()}"

    dcid_len = bytes_data[5]
    pos = 6
    if pos + dcid_len > len(bytes_data):
        parsed["error"] = "Invalid DCID length"
        return parsed
    dcid = bytes_data[pos:pos + dcid_len]
    parsed["DCID Length"] = dcid_len
    parsed["DCID"] = dcid.hex()
    pos += dcid_len

    if pos >= len(bytes_data):
        parsed["error"] = "Missing SCID length"
        return parsed
    scid_len = bytes_data[pos]
    pos += 1

    if pos + scid_len > len(bytes_data):
        parsed["error"] = "Invalid SCID length"
        return parsed
    scid = bytes_data[pos:pos + scid_len]
    parsed["SCID Length"] = scid_len
    parsed["SCID"] = scid.hex()
    pos += scid_len

    parsed["Payload"] = bytes_data[pos:].hex()

    frames, err = decrypt_initial_payload(hex_string)
    if frames:
        parsed["Decrypted Frames"] = frames
    if err:
        parsed["Decryption Error"] = err

    return parsed

def parse_output(file_path):
    responses = defaultdict(list)
    current_mutation = None

    with open(file_path, 'r') as f:
        lines = list(f)
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("Worker processing:"):
                match = re.search(r'Mutation (\d+)', line)
                if match:
                    current_mutation = int(match.group(1))

            elif line.startswith("Got ") and current_mutation is not None:
                if i + 1 < len(lines):
                    hex_payload = lines[i + 1].strip()
                    if hex_payload:
                        breakdown = parse_quic_long_header(hex_payload)
                        responses[current_mutation].append(breakdown)
                    i += 1  # skip next line
            elif line.startswith("No response"):
                current_mutation = None

            i += 1

    return responses

def print_summary(responses):
    for mutation_id, packets in sorted(responses.items()):
        print(f"\n=== Mutation {mutation_id} ({len(packets)} packet(s)) ===")
        for idx, pkt in enumerate(packets, 1):
            print(f"\n  Packet {idx}:")
            for key, value in pkt.items():
                if key == "Decrypted Frames":
                    print("    Decrypted Frames:")
                    for frame in value:
                        print(f"      - {frame}")
                else:
                    print(f"    {key}: {value}")

if __name__ == "__main__":
    filepath = "output.txt"
    parsed_packets = parse_output(filepath)
    print_summary(parsed_packets)
