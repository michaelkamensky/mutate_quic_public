package fuzzing_functions

import "math/rand"

func MutatePaddingDCID(data []byte) BufferSet {
	if len(data) < 6 {
		return ReturnBufferSet([][]byte{data})
	}

	origDCIDLen := int(data[5])
	pos := 6

	if pos+origDCIDLen > len(data) {
		return ReturnBufferSet([][]byte{data})
	}

	var variants [][]byte

	// Strip original DCID, start from base packet with DCID removed
	base := append([]byte(nil), data...)
	base = append(base[:pos], base[pos+origDCIDLen:]...)
	base[5] = 0

	for dcidLen := 0; dcidLen <= 20; dcidLen++ {
		// Variant 1: Random bytes
		randomDCID := make([]byte, dcidLen)
		rand.Read(randomDCID)
		vRand := append([]byte(nil), base...)
		vRand = append(vRand[:pos], append(randomDCID, vRand[pos:]...)...)
		vRand[5] = byte(dcidLen)
		variants = append(variants, vRand)

		// Variant 2: Zero bytes
		zeroDCID := make([]byte, dcidLen) // already zero-filled
		vZero := append([]byte(nil), base...)
		vZero = append(vZero[:pos], append(zeroDCID, vZero[pos:]...)...)
		vZero[5] = byte(dcidLen)
		variants = append(variants, vZero)
	}

	return ReturnBufferSet(variants)
}