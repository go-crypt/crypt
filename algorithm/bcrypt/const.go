package bcrypt

import (
	"github.com/go-crypt/crypt/algorithm"
)

const (
	// EncodingFmt is the encoding format for this algorithm.
	EncodingFmt = "$%s$%d$%s%s"

	// EncodingFmtSHA256 is the encoding format for the SHA256 variant of this algorithm.
	EncodingFmtSHA256 = "$%s$v=2,t=%s,r=%d$%s$%s"

	// AlgName is the name for this algorithm.
	AlgName = "bcrypt"

	// AlgIdentifier is the identifier used in this algorithm.
	AlgIdentifier = "2b"

	// AlgIdentifierVariantSHA256 is the identifier used in encoded SHA256 variant of this algorithm.
	AlgIdentifierVariantSHA256 = "bcrypt-sha256"

	// AlgIdentifierVerA is the identifier used in this algorithm (version a).
	AlgIdentifierVerA = "2a"

	// AlgIdentifierVerX is the identifier used in this algorithm (version x).
	AlgIdentifierVerX = "2x"

	// AlgIdentifierVerY is the identifier used in this algorithm (version y).
	AlgIdentifierVerY = "2y"

	// AlgIdentifierUnversioned is the identifier used in this algorithm (no version).
	AlgIdentifierUnversioned = "2"

	// VariantNameStandard is the variant name of the bcrypt.VariantStandard.
	VariantNameStandard = "standard"

	// VariantNameSHA256 is the variant name of the bcrypt.VariantSHA256.
	VariantNameSHA256 = algorithm.DigestSHA256

	// IterationsMin is the minimum iterations accepted.
	IterationsMin = 10

	// IterationsMax is the maximum iterations accepted.
	IterationsMax = 31

	// IterationsDefault is the default iterations.
	IterationsDefault = 13

	// PasswordInputSizeMax is the maximum password input size accepted.
	PasswordInputSizeMax = 72

	variantDefault = VariantStandard
)

const (
	oV = "v"
	oT = "t"
	oR = "r"
)
