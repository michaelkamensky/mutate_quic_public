package fuzzing_functions

import (
	"math/rand"
	"time"
)

func decodeVarInt(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch b[0] >> 6 {
	case 0:
		return uint64(b[0] & 0x3F), 1
	case 1:
		if len(b) < 2 {
			return 0, 0
		}
		return uint64(b[0]&0x3F)<<8 | uint64(b[1]), 2
	case 2:
		if len(b) < 4 {
			return 0, 0
		}
		val := uint64(b[0]&0x3F)
		for i := 1; i < 4; i++ {
			val = (val << 8) | uint64(b[i])
		}
		return val, 4
	case 3:
		if len(b) < 8 {
			return 0, 0
		}
		val := uint64(b[0]&0x3F)
		for i := 1; i < 8; i++ {
			val = (val << 8) | uint64(b[i])
		}
		return val, 8
	default:
		return 0, 0
	}
}

func encodeVarInt(buf []byte, value uint64) {
	switch len(buf) {
	case 1:
		buf[0] = byte(0x00 | (value & 0x3F))
	case 2:
		buf[0] = 0x40 | byte((value>>8)&0x3F)
		buf[1] = byte(value)
	case 4:
		buf[0] = 0x80 | byte((value>>24)&0x3F)
		buf[1] = byte(value >> 16)
		buf[2] = byte(value >> 8)
		buf[3] = byte(value)
	case 8:
		buf[0] = 0xC0 | byte((value>>56)&0x3F)
		for i := 1; i < 8; i++ {
			buf[i] = byte(value >> (8 * (7 - i)))
		}
	}
}

func MutateLengthTamper(data []byte) BufferSet {
	if len(data) < 6 {
		return ReturnBufferSet([][]byte{data})
	}

	pos := 6
	if pos >= len(data) {
		return ReturnBufferSet([][]byte{data})
	}

	dcidLen := int(data[5])
	if pos+dcidLen > len(data) {
		return ReturnBufferSet([][]byte{data})
	}
	pos += dcidLen

	if pos >= len(data) {
		return ReturnBufferSet([][]byte{data})
	}
	scidLen := int(data[pos])
	pos++
	if pos+scidLen > len(data) {
		return ReturnBufferSet([][]byte{data})
	}
	pos += scidLen

	tokenLen, tokenVarBytes := decodeVarInt(data[pos:])
	if tokenVarBytes == 0 {
		return ReturnBufferSet([][]byte{data})
	}
	pos += tokenVarBytes + int(tokenLen)
	if pos >= len(data) {
		return ReturnBufferSet([][]byte{data})
	}

	lengthStart := pos
	_, lenVarBytes := decodeVarInt(data[lengthStart:])
	if lenVarBytes == 0 || lengthStart+lenVarBytes > len(data) {
		return ReturnBufferSet([][]byte{data})
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var variants [][]byte

	// ZERO variant
	vZero := append([]byte(nil), data...)
	encodeVarInt(vZero[lengthStart:lengthStart+lenVarBytes], 0)
	variants = append(variants, vZero)

	// MAX variant
	var maxVal uint64
	switch lenVarBytes {
	case 1:
		maxVal = (1 << 6) - 1 // 63
	case 2:
		maxVal = (1 << 14) - 1 // 16,383
	case 4:
		maxVal = (1 << 30) - 1 // ~1.07 billion
	case 8:
		// 🔥 THEORETICAL MAX for firewall bypass/exhaustion
		maxVal = 65535 // max UDP payload size
	}

	vMax := append([]byte(nil), data...)
	encodeVarInt(vMax[lengthStart:lengthStart+lenVarBytes], maxVal)
	variants = append(variants, vMax)

	// 10 RANDOM values in [1, maxVal-1]
	for i := 0; i < 10; i++ {
		val := uint64(r.Int63n(int64(maxVal-1))) + 1 // in [1, maxVal-1]
		vRand := append([]byte(nil), data...)
		encodeVarInt(vRand[lengthStart:lengthStart+lenVarBytes], val)
		variants = append(variants, vRand)
	}

	return ReturnBufferSet(variants)
}