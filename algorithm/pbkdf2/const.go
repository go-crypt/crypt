package pbkdf2

import (
	"math"
)

const (
	// EncodingFmt is the encoding format for this algorithm.
	EncodingFmt = "$%s$%d$%s$%s"

	// AlgName is the name for this algorithm.
	AlgName = "pbkdf2"

	// AlgIdentifier is the identifier used in encoded digests for this algorithm.
	AlgIdentifier = AlgName

	// AlgIdentifierSHA1 is the identifier used in encoded SHA1 variants of this algorithm.
	AlgIdentifierSHA1 = "pbkdf2-sha1"

	// AlgIdentifierSHA224 is the identifier used in encoded SHA224 variants of this algorithm.
	AlgIdentifierSHA224 = "pbkdf2-sha224"

	// AlgIdentifierSHA256 is the identifier used in encoded SHA256 variants of this algorithm.
	AlgIdentifierSHA256 = "pbkdf2-sha256"

	// AlgIdentifierSHA384 is the identifier used in encoded SHA384 variants of this algorithm.
	AlgIdentifierSHA384 = "pbkdf2-sha384"

	// AlgIdentifierSHA512 is the identifier used in encoded SHA512 variants of this algorithm.
	AlgIdentifierSHA512 = "pbkdf2-sha512"

	// TagSizeMax is the maximum tag size accepted.
	TagSizeMax = math.MaxInt32

	// SaltSizeMin is the minimum salt size accepted.
	SaltSizeMin = 8

	// SaltSizeMax is the maximum salt size accepted.
	SaltSizeMax = math.MaxInt32

	// IterationsMin is the minimum iterations accepted.
	IterationsMin = 100000

	// IterationsMax is the maximum iterations accepted.
	IterationsMax = math.MaxInt32

	// IterationsDefaultSHA1 is the default iterations for algorithms SHA1 and SHA224.
	IterationsDefaultSHA1 = 720000

	// IterationsDefaultSHA256 is the default iterations for algorithms SHA256 and SHA384.
	IterationsDefaultSHA256 = 310000

	// IterationsDefaultSHA512 is the default iterations for algorithms SHA512.
	IterationsDefaultSHA512 = 120000

	variantDefault = VariantSHA256
)
