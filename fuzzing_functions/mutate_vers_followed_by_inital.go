package fuzzing_functions

import (
	"encoding/binary"
)

// PrecursorVersionNegotiationThenInitial builds a QUIC Version Negotiation
// packet using the same DCID/SCID as the Initial. It is returned first,
// followed by the original Initial.
func PrecursorVersionNegotiationThenInitial(initial []byte) BufferSet {
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
	// Assemble the Version Negotiation Packet
	//--------------------------------------------------------------
	const firstByte byte = 0x80 // 1xxx xxxx: Header Form = 1, rest unused
	vnp := []byte{firstByte}

	// Version = 0x00000000 for version negotiation
	vnp = append(vnp, []byte{0x00, 0x00, 0x00, 0x00}...)

	vnp = append(vnp, byte(dcidLen))
	vnp = append(vnp, dcid...)
	vnp = append(vnp, byte(scidLen))
	vnp = append(vnp, scid...)

	// Supported Versions (add 3 spoofed ones)
	supported := []uint32{
		0x00000001, // QUIC v1
		0xdeadbeef, // spoof
		0xfaceb00c, // spoof
	}

	for _, ver := range supported {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, ver)
		vnp = append(vnp, buf...)
	}

	//--------------------------------------------------------------
	// Return Version Negotiation first, then the untouched Initial
	//--------------------------------------------------------------
	return ReturnBufferSet([][]byte{
		vnp,
		append([]byte(nil), initial...),
	})
}
