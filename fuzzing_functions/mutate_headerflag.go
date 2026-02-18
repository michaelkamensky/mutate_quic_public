package fuzzing_functions

func MutateHeaderFlagsFlip(data []byte) BufferSet {
	if len(data) == 0 {
		// nothing to mutate
		return ReturnBufferSet([][]byte{data})
	}

	const reservedMask byte = 0x0C // bits 3 and 2
	const flagMask     byte = 0x01 // bit 0 (“last unassigned flag”)

	origFirst := data[0]
	baseFirst := origFirst &^ (reservedMask | flagMask) // clear our fuzz bits

	var variants [][]byte

	// Iterate over all 4 combinations of the two reserved bits.
	for reservedVal := byte(0); reservedVal <= reservedMask; reservedVal += 0x04 {
		// First: flag bit = 1
		{
			newFirst := baseFirst | reservedVal | flagMask
			mut := append([]byte(nil), data...)
			mut[0] = newFirst
			variants = append(variants, mut)
		}

		// Second: flag bit = 0
		{
			newFirst := baseFirst | reservedVal
			mut := append([]byte(nil), data...)
			mut[0] = newFirst
			variants = append(variants, mut)
		}
	}

	return ReturnBufferSet(variants)
}
