package scrypt

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/validate"
)

// Opt describes the functional option pattern for the scrypt.Hasher.
type Opt = algorithm.Opt[*Hasher]

// WithVariant configures the scrypt.Variant of the resulting scrypt.Digest.
// Default is scrypt.VariantScrypt.
func WithVariant(variant Variant) Opt {
	return func(h *Hasher) (err error) {
		switch variant {
		case VariantNone:
			return nil
		case VariantScrypt, VariantYescrypt:
			h.variant = variant

			return nil
		default:
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf("%w: variant '%d' is invalid", algorithm.ErrParameterInvalid, variant))
		}
	}
}

// WithVariantName uses the variant name or identifier to configure the scrypt.Variant of the resulting scrypt.Digest.
// Default is scrypt.VariantScrypt.
func WithVariantName(identifier string) Opt {
	return func(h *Hasher) (err error) {
		if identifier == "" {
			return nil
		}

		variant := NewVariant(identifier)

		if variant == VariantNone {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf("%w: variant identifier '%s' is invalid", algorithm.ErrParameterInvalid, identifier))
		}

		h.variant = variant

		return nil
	}
}

// WithK adjusts the key length of the resulting scrypt.Digest.
// Minimum is 1, Maximum is 137438953440. Default is 32.
func WithK(k int) Opt {
	return func(h *Hasher) (err error) {
		if err = validate.Range(algorithm.ErrParameterInvalid, "key length", k, KeyLengthMin, KeyLengthMax); err != nil {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, err)
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
		if err = validate.Range(algorithm.ErrParameterInvalid, "salt length", s, SaltLengthMin, SaltLengthMax); err != nil {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, err)
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
		if err = validate.Range(algorithm.ErrParameterInvalid, "iterations", ln, IterationsMin, IterationsMax); err != nil {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, err)
		}

		h.ln = ln

		return nil
	}
}

// WithR sets the r parameter (block size) of the resulting scrypt.Digest.
// Minimum is 1, Maximum is math.MaxInt / 256. Default is 8.
func WithR(r int) Opt {
	return func(h *Hasher) (err error) {
		if err = validate.Range(algorithm.ErrParameterInvalid, "block size", r, BlockSizeMin, BlockSizeMax); err != nil {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, err)
		}

		h.r = r

		return nil
	}
}

// WithBlockSize is an alias for WithR.
func WithBlockSize(r int) Opt {
	return WithR(r)
}

// WithP sets the p parameter (parallelism factor) of the resulting scrypt.Digest.
// Minimum is 1, Maximum is 1073741823. Default is 1. The yescrypt variant only supports a value of 1.
func WithP(p int) Opt {
	return func(h *Hasher) (err error) {
		if err = validate.Range(algorithm.ErrParameterInvalid, "parallelism", p, ParallelismMin, ParallelismMax); err != nil {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, err)
		}

		h.p = p

		return nil
	}
}

// WithParallelism is an alias for WithP.
func WithParallelism(p int) Opt {
	return WithP(p)
}
