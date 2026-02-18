package fuzzing_functions

import "math/rand"

func MutatePaddingSCID(data []byte) BufferSet {
	if len(data) < 6 {
		//creating the buffer set that will be returned
		bs := BufferSet{
			Buffers: [][]byte{data},
		}

		// returning the bufferset
		return bs
	}
	dcidLen := int(data[5])
	pos := 6 + dcidLen
	if pos >= len(data) {
		//creating the buffer set that will be returned
		bs := BufferSet{
			Buffers: [][]byte{data},
		}

		// returning the bufferset
		return bs
	}
	scidLen := int(data[pos])
	pos++
	if pos+scidLen > len(data) {
		//creating the buffer set that will be returned
		bs := BufferSet{
			Buffers: [][]byte{data},
		}

		// returning the bufferset
		return bs
	}
	if scidLen >= 20 {
		//creating the buffer set that will be returned
		bs := BufferSet{
			Buffers: [][]byte{data},
		}

		// returning the bufferset
		return bs
	}
	padding := make([]byte, 20-scidLen)
	rand.Read(padding)
	copyData := append([]byte(nil), data...)
	copyData = append(copyData[:pos+scidLen], append(padding, copyData[pos+scidLen:]...)...)
	copyData[6+dcidLen] = 20
	//creating the buffer set that will be returned
	bs := BufferSet{
        Buffers: [][]byte{copyData},
    }

	// returning the bufferset
	return bs
}
