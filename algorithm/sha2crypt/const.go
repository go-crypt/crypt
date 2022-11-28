package sha2crypt

const (
	// EncodingFmt is the encoding format for this algorithm.
	EncodingFmt = "$%s$rounds=%d$%s$%s"

	// AlgName is the name for this algorithm.
	AlgName = "sha2crypt"

	// AlgIdentifierSHA256 is the identifier used in encoded SHA256 variants of this algorithm.
	AlgIdentifierSHA256 = "5"

	// AlgIdentifierSHA512 is the identifier used in encoded SHA512 variants of this algorithm.
	AlgIdentifierSHA512 = "6"

	// IterationsMin is the minimum number of iterations accepted.
	IterationsMin = 1000

	// IterationsMax is the maximum number of iterations accepted.
	IterationsMax = 999999999

	// IterationsDefaultSHA256 is the default number of iterations for SHA256.
	IterationsDefaultSHA256 = 1000000

	// IterationsDefaultSHA512 is the default number of iterations for SHA512.
	IterationsDefaultSHA512 = 500000

	// SaltSizeMin is the minimum salt length.
	SaltSizeMin = 1

	// SaltSizeMax is the maximum salt length.
	SaltSizeMax = 16

	// SaltCharSet are the valid characters for the salt.
	SaltCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"
)