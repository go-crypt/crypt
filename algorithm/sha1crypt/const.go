package sha1crypt

import (
	"math"
)

const (
	// EncodingFmt is the encoding format for this algorithm.
	EncodingFmt = "$sha1$%d$%s$%s"

	// AlgName is the name for this algorithm.
	AlgName = "sha1crypt"

	// AlgIdentifier is the identifier used in this algorithm.
	AlgIdentifier = "sha1"

	// SaltLengthMin is the minimum salt size accepted.
	SaltLengthMin = 0

	// SaltLengthMax is the maximum salt size accepted.
	SaltLengthMax = 64

	// SaltLengthDefault is the default salt size.
	SaltLengthDefault = 8

	// SaltCharSet are the valid characters for the salt.
	SaltCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"

	// IterationsMin is the minimum iterations accepted.
	IterationsMin = 0

	// IterationsMax is the maximum iterations accepted.
	IterationsMax uint32 = math.MaxUint32

	// IterationsDefault is the default iterations.
	IterationsDefault = 480000
)
