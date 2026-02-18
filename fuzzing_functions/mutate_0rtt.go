package fuzzing_functions

import "math/rand"

func Mutate0RTTInjection(data []byte) BufferSet {
	copyData := append([]byte(nil), data...)
	randData := make([]byte, 50)
	rand.Read(randData)
	copyData = append(copyData, randData...)

	//creating the buffer set that will be returned
	bs := BufferSet{
        Buffers: [][]byte{copyData},
    }

	// returning the bufferset
	return bs
}