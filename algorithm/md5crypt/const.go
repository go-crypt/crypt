package md5crypt

import (
	"math"
)

const (
	// EncodingFmt is the encoding format for this algorithm.
	EncodingFmt = "$1$%s$%s"

	// EncodingFmtSun is the encoding format for this algorithm when using md5crypt.VariantSun.
	EncodingFmtSun = "$md5$%s$$%s"

	// EncodingFmtSunIterations is the encoding format for this algorithm when using md5crypt.VariantSun and iterations more than 0.
	EncodingFmtSunIterations = "$md5,iterations=%d$%s$$%s"

	// AlgName is the name for this algorithm.
	AlgName = "md5crypt"

	// AlgIdentifier is the identifier used in this algorithm.
	AlgIdentifier = "1"

	// AlgIdentifierVariantSun is the identifier used in this algorithm when using md5crypt.VariantSun.
	AlgIdentifierVariantSun = "md5"

	// VariantNameStandard is the md5crypt.Variant name for md5crypt.VariantStandard.
	VariantNameStandard = "standard"

	// VariantNameSun is the md5crypt.Variant name for md5crypt.VariantSun.
	VariantNameSun = "sun"

	// SaltLengthMin is the minimum salt size accepted.
	SaltLengthMin = 1

	// SaltLengthMax is the maximum salt size accepted.
	SaltLengthMax = 8

	// SaltLengthDefault is the default salt size.
	SaltLengthDefault = SaltLengthMax

	// SaltCharSet are the valid characters for the salt.
	SaltCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"

	// IterationsMin is the minimum iterations accepted.
	IterationsMin = 0

	// IterationsDefault is the default iterations.
	IterationsDefault = 34000

	// IterationsMax is the maximum iterations accepted.
	IterationsMax uint32 = math.MaxUint32
)

const (
	variantDefault = VariantStandard
)
