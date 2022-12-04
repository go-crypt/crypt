package scrypt

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// Opt describes the functional option pattern for the scrypt.Hasher.
type Opt func(h *Hasher) (err error)

// WithK adjusts the key length of the resulting scrypt.Digest.
// Minimum is 1, Maximum is 137438953440. Default is 32.
func WithK(k int) Opt {
	return func(h *Hasher) (err error) {
		if k < KeyLengthMin || k > KeyLengthMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "key length", KeyLengthMin, "", KeyLengthMax, k))
		}

		h.k = k

		return nil
	}
}

// WithKeyLength is an alias for WithK.
func WithKeyLength(k int) Opt {
	return WithK(k)
}

// WithS adjusts the salt length of the resulting scrypt.Digest.
// Minimum is 8, Maximum is 1024. Default is 16.
func WithS(s int) Opt {
	return func(h *Hasher) (err error) {
		if s < SaltLengthMin || s > SaltLengthMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "salt length", SaltLengthMin, "", SaltLengthMax, s))
		}

		h.bytesSalt = s

		return nil
	}
}

// WithSaltLength is an alias for WithS.
func WithSaltLength(s int) Opt {
	return WithS(s)
}

// WithLN sets the ln parameter (logN) of the resulting scrypt.Digest.
// Minimum is 1, Maximum is 58. Default is 16.
func WithLN(ln int) Opt {
	return func(h *Hasher) (err error) {
		if ln < IterationsMin || ln > IterationsMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "iterations", IterationsMin, "", IterationsMax, ln))
		}

		h.ln = ln

		return nil
	}
}

// WithR sets the r parameter (block size) of the resulting scrypt.Digest.
// Minimum is 1, Maximum is math.MaxInt / 256. Default is 8.
func WithR(r int) Opt {
	return func(h *Hasher) (err error) {
		if r < BlockSizeMin || r > BlockSizeMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "block size", BlockSizeMin, "", BlockSizeMax, r))
		}

		h.r = r

		return nil
	}
}

// WithBlockSize is an alias for WithR.
func WithBlockSize(r int) Opt {
	return WithS(r)
}

// WithP sets the p parameter (parallelism factor) of the resulting scrypt.Digest.
// Minimum is 1, Maximum is 1073741823. Default is 1.
func WithP(p int) Opt {
	return func(h *Hasher) (err error) {
		if p < ParallelismMin || p > ParallelismMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "parallelism", ParallelismMin, "", ParallelismMax, p))
		}

		h.p = p

		return nil
	}
}

// WithParallelism is an alias for WithP.
func WithParallelism(p int) Opt {
	return WithP(p)
}
