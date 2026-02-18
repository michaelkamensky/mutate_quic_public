package fuzzing_functions

import (
	"encoding/binary"
	"math/rand"
	"time"
)

func MutateVersionSpoofing(data []byte) BufferSet {
	if len(data) < 5 {
		return ReturnBufferSet([][]byte{data})
	}

	var versions = []uint32{
		0x00000000, // reserved
		0x00000001, // QUIC v1
		0x0a0a0a0a, // FB internal/test
		0xfaceb00c, // greased/test
		0xdeadbeef, // high-entropy
		0x51303530, // "Q050" Google draft
		0xaaaaaaaa, // alternating 1s
		0x55555555, // alternating 0s
		0xffffffff, // max uint32
		0x01020304, // ascending
		0x04030201, // descending
	}

	// Add 20 random versions (some could be valid/invalid)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 20; i++ {
		versions = append(versions, r.Uint32())
	}

	var variants [][]byte

	for _, v := range versions {
		copyData := append([]byte(nil), data...)
		binary.BigEndian.PutUint32(copyData[1:5], v)
		variants = append(variants, copyData)
	}

	return ReturnBufferSet(variants)
}