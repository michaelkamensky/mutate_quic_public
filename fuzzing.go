package main

import (
	"quic_capture/fuzzing_functions"
)

type MutationFunc func([]byte) fuzzing_functions.BufferSet
func GetMutationFunc(id int) MutationFunc {
	switch id {
	case 1:
		return fuzzing_functions.MutateVersionSpoofing
	case 2:
		return fuzzing_functions.MutatePaddingDCID
	case 3:
		return fuzzing_functions.MutatePaddingSCID
	case 4:
		return fuzzing_functions.Mutate0RTTInjection
	case 5:
		return fuzzing_functions.MutateHeaderFlagsFlip
	case 6:
		return fuzzing_functions.MutateLengthTamper
	case 7:
		return fuzzing_functions.Precursor0RTTThenInitial
	case 8:
		return fuzzing_functions.PrecursorHandshakeThenInitial
	case 9:
		return fuzzing_functions.PrecursorRetryThenInitial
	case 10:
		return fuzzing_functions.PrecursorVersionNegotiationThenInitial
	default:
		return func(data []byte) fuzzing_functions.BufferSet { return fuzzing_functions.BufferSet{Buffers: [][]byte{},} }
	}
}
