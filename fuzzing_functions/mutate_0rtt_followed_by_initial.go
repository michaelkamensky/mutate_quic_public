package fuzzing_functions



// Precursor0RTTThenInitial builds a well-formed 0-RTT packet that reuses the
// IDs and Version of an Initial packet.  The caller should send buffers[0]
// first (0-RTT) and buffers[1] next (original Initial) from the SAME UDP
// socket so the 5-tuple is identical.
func Precursor0RTTThenInitial(initial []byte) BufferSet {
	// Need at least header --> Version --> DCID-len
	if len(initial) < 6 {
		return ReturnBufferSet([][]byte{initial})
	}

	//--------------------------------------------------------------
	// Parse DCID / SCID from the Initial
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
				  0x10 |               // Long-Packet-Type = 01 (0-RTT)
				  reserved | pnLenBits

	//--------------------------------------------------------------
	// Assemble the 0-RTT packet
	//--------------------------------------------------------------
	var zeroRTT []byte
	zeroRTT = append(zeroRTT, firstByte)          // byte 0
	zeroRTT = append(zeroRTT, initial[1:5]...)     // Version
	zeroRTT = append(zeroRTT, byte(dcidLen))       // DCID-len
	zeroRTT = append(zeroRTT, dcid...)             // DCID
	zeroRTT = append(zeroRTT, byte(scidLen))       // SCID-len
	zeroRTT = append(zeroRTT, scid...)             // SCID

	// Length = pnLen (no payload).  pnLen = bits+1 (1..4).
	pnLen := int(pnLenBits) + 1
	lengthField := encodeVarInt1Byte(uint64(pnLen)) // always ≤4
	zeroRTT = append(zeroRTT, lengthField)

	// Packet-Number: all zeros of chosen length
	for i := 0; i < pnLen; i++ {
		zeroRTT = append(zeroRTT, 0x00)
	}
	// No payload for precursor

	//--------------------------------------------------------------
	// Return 0-RTT first, then the untouched Initial
	//--------------------------------------------------------------
	return ReturnBufferSet([][]byte{zeroRTT, append([]byte(nil), initial...)})
}