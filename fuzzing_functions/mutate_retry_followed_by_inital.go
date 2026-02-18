package fuzzing_functions

import (
	"math/rand"
	"time"
)

// PrecursorRetryThenInitial builds a minimal, syntactically-correct Retry
// packet that reuses Version, DCID, and SCID from the supplied Initial.
// It is returned first in the BufferSet; the second buffer is the original
// Initial.  Send them back-to-back on the SAME UDP connection.
func PrecursorRetryThenInitial(initial []byte) BufferSet {
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
	// Assemble the Retry packet
	//--------------------------------------------------------------
	const firstByte byte = 0xF0 // 1111 0000: Form=1, Fixed=1, Type=3 (Retry), Unused=0
	retry := []byte{firstByte}
	retry = append(retry, initial[1:5]...)       // Version
	retry = append(retry, byte(dcidLen))         // DCID length
	retry = append(retry, dcid...)               // DCID
	retry = append(retry, byte(scidLen))         // SCID length
	retry = append(retry, scid...)               // SCID

	// --- Retry Token: 8 random bytes (could be 0-length; random looks realistic) ---
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	token := make([]byte, 8)
	r.Read(token)
	retry = append(retry, token...)

	// --- Retry Integrity Tag: 16 placeholder bytes (zeros) ---
	retry = append(retry, make([]byte, 16)...)

	//--------------------------------------------------------------
	// Return Retry precursor, then the original Initial
	//--------------------------------------------------------------
	return ReturnBufferSet([][]byte{
		retry,
		append([]byte(nil), initial...),
	})
}
