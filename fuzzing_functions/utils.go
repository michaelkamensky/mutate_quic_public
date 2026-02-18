package fuzzing_functions

// struct to help have multiple bytes buff into one so it can be passed upwards
type BufferSet struct {
    Buffers [][]byte
}

func ReturnBufferSet(buffers [][]byte) BufferSet {
	bs := BufferSet{
		Buffers: buffers,
	}
	return bs
}

// encodeVarInt1Byte encodes v (≤63) as a 1-byte QUIC varint (prefix 00).
func encodeVarInt1Byte(v uint64) byte { return byte(v & 0x3F) }