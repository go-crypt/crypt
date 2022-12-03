package argon2

import (
	"math"
)

const (
	argon2i  = "argon2i"
	argon2d  = "argon2d"
	argon2id = "argon2id"
)

const (
	// EncodingFmt is the encoding format for this algorithm.
	EncodingFmt = "$%s$v=%d$m=%d,t=%d,p=%d$%s$%s"

	// AlgName is the name for this algorithm.
	AlgName = "argon2"

	// AlgIdentifierVariantI is the identifier used in encoded argon2i variants of this algorithm.
	AlgIdentifierVariantI = argon2i

	// AlgIdentifierVariantD is the identifier used in encoded argon2d variants of this algorithm.
	AlgIdentifierVariantD = argon2d

	// AlgIdentifierVariantID is the identifier used in encoded argon2id variants of this algorithm.
	AlgIdentifierVariantID = argon2id

	// TagLengthMin is the minimum tag length output.
	TagLengthMin = 4

	// TagLengthMax is the maximum tag length output.
	TagLengthMax = math.MaxInt32

	// SaltSizeMin is the minimum salt length input/output.
	SaltSizeMin = 1

	// SaltSizeMax is the maximum salt length input/output.
	SaltSizeMax = math.MaxInt32

	// PassesMin is the minimum number of passes input.
	PassesMin = 1

	// PassesMax is the maximum number of passes input.
	PassesMax = math.MaxInt32

	// ParallelismMin is the minimum parallelism factor input.
	ParallelismMin = 1

	// ParallelismMax is the maximum parallelism factor input.
	ParallelismMax = 16777215

	// MemoryMinParallelismMultiplier is the parallelism multiplier which determines the minimum memory.
	MemoryMinParallelismMultiplier = 8

	// MemoryRoundingParallelismMultiplier is the parallelism multiplier which determines the actual memory value. The
	// value is the closest multiple of this multiplied by the parallelism input.
	MemoryRoundingParallelismMultiplier = 4

	// MemoryMax is the maximum input for memory.
	MemoryMax = math.MaxInt32

	// PasswordInputSizeMax is the maximum input for the password content.
	PasswordInputSizeMax = math.MaxInt32

	variantArgon2Default = VariantID
)

const (
	oV = "v"
	oK = "k"
	oM = "m"
	oT = "t"
	oP = "p"
)
