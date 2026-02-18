package fuzzing_functions


// PrecursorHandshakeThenInitial builds a well-formed QUIC Handshake packet
// that mimics a real connection (using the same IDs and Version from the Initial).
// The 5-tuple must remain the same between the packets (same UDP socket).
func PrecursorHandshakeThenInitial(initial []byte) BufferSet {
	if len(initial) < 6 {
		return ReturnBufferSet([][]byte{initial})
	}

	//--------------------------------------------------------------
	// Parse DCID / SCID from Initial
	//--------------------------------------------------------------
	pos := 6
	dcidLen := int(initial[5])
	if pos+dcidLen > len(initial) {
		return ReturnBufferSet([][]byte{initial})
	}
	dcid := initial[pos : pos+dcidLen]
	pos += dcidLen

	if pos >= len(initial) {
		return ReturnBufferSet([][]byte{initial})
	}
	scidLen := int(initial[pos])
	pos++
	if pos+scidLen > len(initial) {
		return ReturnBufferSet([][]byte{initial})
	}
	scid := initial[pos : pos+scidLen]

	//--------------------------------------------------------------
	// Derive header-field bits
	//--------------------------------------------------------------
	origFirst := initial[0]
	pnLenBits := origFirst & 0x03       // keep original packet-number length
	reserved   := origFirst & 0x0C      // keep reserved bits as in Initial
	firstByte  := (origFirst & 0xC0) |  // HeaderForm + Fixed stay the same
				  0x20 |               // Long-Packet-Type = 10 (Handshake)
				  reserved | pnLenBits

	//--------------------------------------------------------------
	// Assemble the Handshake packet
	//--------------------------------------------------------------
	var handshake []byte
	handshake = append(handshake, firstByte)           // byte 0
	handshake = append(handshake, initial[1:5]...)     // Version
	handshake = append(handshake, byte(dcidLen))       // DCID length
	handshake = append(handshake, dcid...)             // DCID
	handshake = append(handshake, byte(scidLen))       // SCID length
	handshake = append(handshake, scid...)             // SCID

	// Length = pnLen (no payload).  pnLen = bits+1 (1..4).
	pnLen := int(pnLenBits) + 1
	lengthField := encodeVarInt1Byte(uint64(pnLen)) // always ≤ 63
	handshake = append(handshake, lengthField)

	// Packet-Number: all zeros of chosen length
	for i := 0; i < pnLen; i++ {
		handshake = append(handshake, 0x00)
	}
	// No payload

	//--------------------------------------------------------------
	// Return Handshake then the untouched Initial
	//--------------------------------------------------------------
	return ReturnBufferSet([][]byte{
		handshake,
		append([]byte(nil), initial...),
	})
}
