package scrypt

import (
	"math"
)

const (
	// EncodingFormat is the format of the encoded digest.
	EncodingFormat = "$%s$ln=%d,r=%d,p=%d$%s$%s"

	// AlgName is the name for this algorithm.
	AlgName = "scrypt"

	// KeyLengthMin is the minimum key length accepted.
	KeyLengthMin = 1

	// SaltLengthMin is the minimum salt length accepted.
	SaltLengthMin = 8

	// SaltLengthMax is the maximum salt length accepted.
	SaltLengthMax = 1024

	// IterationsMin is the minimum number of iterations accepted.
	IterationsMin = 1

	// IterationsMax is the maximum number of iterations accepted.
	IterationsMax = 58

	// IterationsDefault is the default number of iterations.
	IterationsDefault = 16

	// BlockSizeMin is the minimum block size accepted.
	BlockSizeMin = 1

	// BlockSizeMax is the maximum block size accepted.
	BlockSizeMax = math.MaxInt / 256

	// BlockSizeDefault is the default block size.
	BlockSizeDefault = 8

	// ParallelismMin is the minimum parallelism factor accepted.
	ParallelismMin = 1

	// ParallelismMax is the maximum parallelism factor accepted.
	//
	// Equation is based on the following text from RFC:
	//
	//   The parallelization parameter p
	//   ("parallelizationParameter") is a positive integer less than or equal
	//   to ((2^32-1) * 32) / (128 * r).
	//
	//   When r has a minimum of 1, this makes the equation ((2^32-1) * 32) / 128.
	ParallelismMax = 1073741823

	// ParallelismDefault is the default parallelism factor.
	ParallelismDefault = ParallelismMin
)

const (
	oP  = "p"
	oR  = "r"
	oLN = "ln"
)
