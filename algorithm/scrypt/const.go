package scrypt

import (
	"math"
)

const (
	// EncodingFormat is the format of the encoded digest.
	EncodingFormat = "$%s$ln=%d,r=%d,p=%d$%s$%s"

	// AlgName is the name for this algorithm.
	AlgName = "scrypt"

	// KeySizeMin is the minimum key length accepted.
	KeySizeMin = 1

	// SaltSizeMin is the minimum salt length accepted.
	SaltSizeMin = 8

	// SaltSizeMax is the maximum salt length accepted.
	SaltSizeMax = 1024

	// IterationsMin is the minimum number of iterations accepted.
	IterationsMin = 1

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

	// ParallelismDefault is the default parallelism factor.
	ParallelismDefault = ParallelismMin
)

const (
	oP  = "p"
	oR  = "r"
	oLN = "ln"
)
