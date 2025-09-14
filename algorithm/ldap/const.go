package ldap

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
	AlgIdentifierSHA1 = "SHA"

	// AlgIdentifierSaltedSHA1 is the identifier used in encoded SHA1 salted variants of this algorithm.
	AlgIdentifierSaltedSHA1 = "SSHA"

	// AlgIdentifierSHA256 is the identifier used in encoded SHA256 variants of this algorithm.
	AlgIdentifierSHA256 = "SHA256"

	// AlgIdentifierSaltedSHA256 is the identifier used in encoded SHA256 salted variants of this algorithm.
	AlgIdentifierSaltedSHA256 = "SSHA256"

	// AlgIdentifierSHA512 is the identifier used in encoded SHA512 variants of this algorithm.
	AlgIdentifierSHA512 = "SHA512"

	// AlgIdentifierSaltedSHA512 is the identifier used in encoded SHA512 salted variants of this algorithm.
	AlgIdentifierSaltedSHA512 = "SSHA512"

	// SaltLengthMin is the minimum salt size accepted.
	SaltLengthMin = 8

	// SaltLengthMax is the maximum salt size accepted.
	SaltLengthMax = math.MaxInt32

	variantDefault = VariantSaltedSHA512
)
