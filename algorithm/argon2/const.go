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

	// KeyLengthMin is the minimum tag length output.
	KeyLengthMin = 4

	// KeyLengthMax is the maximum tag length output.
	KeyLengthMax = math.MaxInt32

	// KeyLengthDefault is the default key length.
	KeyLengthDefault = 32

	// SaltLengthMin is the minimum salt length input/output.
	SaltLengthMin = 1

	// SaltLengthMax is the maximum salt length input/output.
	SaltLengthMax = math.MaxInt32

	// IterationsMin is the minimum number of passes input.
	IterationsMin = 1

	// IterationsMax is the maximum number of passes input.
	IterationsMax = math.MaxInt32

	// IterationsDefault is the default number of passes.
	IterationsDefault = IterationsMin

	// ParallelismMin is the minimum parallelism factor input.
	ParallelismMin = 1

	// ParallelismMax is the maximum parallelism factor input.
	ParallelismMax = 16777215

	// ParallelismDefault is the default parallelism factor.
	ParallelismDefault = 4

	// MemoryMinParallelismMultiplier is the parallelism multiplier which determines the minimum memory.
	MemoryMinParallelismMultiplier = 8

	// MemoryRoundingParallelismMultiplier is the parallelism multiplier which determines the actual memory value. The
	// value is the closest multiple of this multiplied by the parallelism input.
	MemoryRoundingParallelismMultiplier = 4

	// MemoryMin is the minimum input for memory.
	MemoryMin = ParallelismMin * MemoryMinParallelismMultiplier

	// MemoryMax is the maximum input for memory.
	MemoryMax = math.MaxInt32

	// MemoryDefault represents the default memory value.
	MemoryDefault = 2 * 1024 * 1024

	// PasswordInputSizeMax is the maximum input for the password content.
	PasswordInputSizeMax = math.MaxInt32
)

const (
	variantDefault = VariantID

	oV = "v"
	oK = "k"
	oM = "m"
	oT = "t"
	oP = "p"
)
