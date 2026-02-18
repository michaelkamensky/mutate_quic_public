#!/usr/bin/env python3
"""
Compare a fuzzer session log containing mutated packets with a Suricata eve.json
log and report which packets appear in the IDS output.

Usage:
    python3 json_compare.py <sessionlog.json> <eve.json>
"""

import base64
import binascii
import json
import os
import sys
import traceback
from typing import List, Tuple

# ------------- tiny debug helper ------------------------------------------------
def debug(msg: str) -> None:
    print(f"[DEBUG] {msg}", flush=True)


# ------------- helpers ----------------------------------------------------------
def file_info(path: str) -> None:
    """Print file size and number of lines for quick sanity-checking."""
    try:
        size_mb = os.path.getsize(path) / (1024 * 1024)
        with open(path, "r", errors="replace") as f:
            lines = sum(1 for _ in f)
        debug(f"File: {path}, Size: {size_mb:.2f} MB, Lines: {lines}")
    except Exception as e:
        debug(f"Could not stat {path}: {e}")


def _str_to_hex(s: str) -> str:
    """
    Best-effort conversion of *any* string that might encode binary data to hex.
    Order of attempts:
        1. already-hex? -> return lower-case
        2. base64?      -> decode then hex
        3. raw bytes    -> encode latin-1 then hex
    """
    s = s.strip()

    # 1) looks like hex already?
    is_even_len_hex = len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s)
    if is_even_len_hex:
        return s.lower()

    # 2) try base64
    try:
        decoded = base64.b64decode(s, validate=True)
        return decoded.hex()
    except (binascii.Error, ValueError):
        pass

    # 3) fall back: treat original string as raw bytes
    return s.encode("latin1").hex()


# ------------- load mutated packets --------------------------------------------
def load_mutated_packets(sessionlog_path: str) -> List[str]:
    """Return a list of hex strings representing each mutated packet."""
    mutated_hex: List[str] = []

    try:
        with open(sessionlog_path, "r", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if i % 1000 == 0:
                    debug(f"Session-log lines read: {i}")

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if "mutated" not in entry:
                    continue

                pkt = entry["mutated"]

                # If JSON contained bytes (unlikely) they arrive as list of ints;
                # convert that to bytes first.
                if isinstance(pkt, list):
                    pkt = bytes(pkt)

                # bytes  -> hex
                if isinstance(pkt, (bytes, bytearray)):
                    mutated_hex.append(bytes(pkt).hex())
                # string -> try hex / b64 / latin-1
                elif isinstance(pkt, str):
                    mutated_hex.append(_str_to_hex(pkt))
                else:
                    debug(f"Unrecognised mutated packet type on line {i}: {type(pkt)}")

    except Exception as e:
        debug(f"Failed to parse session log: {e}")
        traceback.print_exc()

    debug(f"Loaded {len(mutated_hex)} mutated packets from session log")
    return mutated_hex


# ------------- match against Suricata ------------------------------------------
SURICATA_PAYLOAD_KEYS = ("payload", "packet", "payload_printable")


def extract_payload_hex(entry: dict) -> str | None:
    """Return hex data from the first recognised Suricata payload field, else None."""
    for k in SURICATA_PAYLOAD_KEYS:
        if k in entry and entry[k]:
            return entry[k].lower()
    return None


def separate_packets(mutated_hex: List[str], eve_path: str) -> Tuple[List[str], List[str]]:
    matched: List[str] = []
    unmatched: List[str] = mutated_hex.copy()  # we'll pop from this as we find matches

    try:
        with open(eve_path, "r", errors="replace") as f:
            for i, line in enumerate(f, 1):
                # progress every 10 k lines
                if i % 10_000 == 0:
                    debug(f"Scanned {i} lines of eve.json")

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                payload_hex = extract_payload_hex(entry)
                if not payload_hex:
                    continue

                # iterate over a *snapshot* of unmatched so we can remove safely
                for pkt_hex in unmatched[:]:
                    # exact substring search
                    if pkt_hex in payload_hex:
                        matched.append(pkt_hex)
                        unmatched.remove(pkt_hex)

                # quick exit if everything matched
                if not unmatched:
                    break

    except Exception as e:
        debug(f"Error while scanning eve.json: {e}")
        traceback.print_exc()

    debug(f"Matching finished: {len(matched)} matched, {len(unmatched)} unmatched")
    return matched, unmatched


# ------------- write helpers ----------------------------------------------------
def write_packets(filename: str, packets: List[str]) -> None:
    try:
        with open(filename, "w") as f:
            for pkt in packets:
                f.write(pkt + "\n")
        debug(f"Wrote {len(packets)} packets → {filename}")
    except Exception as e:
        debug(f"Could not write {filename}: {e}")


# ------------- main -------------------------------------------------------------
def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <sessionlog.json> <eve.json>")
        sys.exit(1)

    sessionlog_path, eve_path = sys.argv[1:3]

    debug("🔎  Starting comparison tool")
    file_info(sessionlog_path)
    file_info(eve_path)

    mutated_hex = load_mutated_packets(sessionlog_path)
    matched, unmatched = separate_packets(mutated_hex, eve_path)

    # summary
    print(f"Total mutated packets: {len(mutated_hex)}")
    print(f"Matched packets       : {len(matched)}")
    print(f"Unmatched packets     : {len(unmatched)}")

    # outputs
    write_packets("matched_packets.log", matched)
    write_packets("unmatched_packets.log", unmatched)
    print("Results written to matched_packets.log and unmatched_packets.log")


if __name__ == "__main__":
    main()
