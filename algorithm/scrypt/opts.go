package scrypt

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// Opt describes the functional option pattern for the scrypt.Hasher.
type Opt func(h *Hasher) (err error)

// WithK adjusts the key size of the resulting Scrypt hash. Default is 32.
func WithK(k int) Opt {
	return func(h *Hasher) (err error) {
		if k < KeySizeMin || k > KeySizeMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "k", KeySizeMin, "", KeySizeMax, k))
		}

		h.k = k

		return nil
	}
}

// WithKeySize is an alias for WithK.
func WithKeySize(k int) Opt {
	return WithK(k)
}

// WithS adjusts the salt size of the resulting Scrypt hash. Default is 16.
func WithS(s int) Opt {
	return func(h *Hasher) (err error) {
		if s < SaltSizeMin || s > SaltSizeMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "s", SaltSizeMin, "", SaltSizeMax, s))
		}

		h.bytesSalt = s

		return nil
	}
}

// WithSaltSize is an alias for WithS.
func WithSaltSize(s int) Opt {
	return WithS(s)
}

// WithLN sets the ln parameter (logN) of the resulting Scrypt hash. Default is 16.
func WithLN(ln int) Opt {
	return func(h *Hasher) (err error) {
		if ln < IterationsMin {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf("%w: parameter 'ln' must be more than %d but is set to '%d'", algorithm.ErrParameterInvalid, IterationsMin, ln))
		}

		h.ln = ln

		return nil
	}
}

// WithR sets the r parameter (block size) of the resulting Scrypt hash. Minimum is 1, Maximum is math.MaxInt / 256. Default is 8.
func WithR(r int) Opt {
	return func(h *Hasher) (err error) {
		if r < BlockSizeMin || r > BlockSizeMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "r", BlockSizeMin, "", BlockSizeMax, r))
		}

		h.r = r

		return nil
	}
}

// WithBlockSize is an alias for WithR.
func WithBlockSize(r int) Opt {
	return WithS(r)
}

// WithP sets the p parameter (parallelism factor) of the resulting Scrypt hash. Minimum is 1, Maximum is 1073741823. Default is 1.
func WithP(p int) Opt {
	return func(h *Hasher) (err error) {
		if p < ParallelismMin || p > ParallelismMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "p", ParallelismMin, "", ParallelismMax, p))
		}

		h.p = p

		return nil
	}
}

// WithParallelism is an alias for WithP.
func WithParallelism(p int) Opt {
	return WithP(p)
}
