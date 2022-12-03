package bcrypt

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
)

// bcrypt constants.
const (
	// CostMin is the minimum cost accepted.
	CostMin = 10

	// CostMax is the maximum cost accepted.
	CostMax = 31

	// CostDefault is the default cost.
	CostDefault = 13

	// PasswordInputSizeMax is the maximum password input size accepted.
	PasswordInputSizeMax = 72

	variantBcryptDefault = VariantStandard
)

const (
	oV = "v"
	oT = "t"
	oR = "r"
)
