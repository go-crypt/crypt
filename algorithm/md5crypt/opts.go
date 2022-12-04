package md5crypt

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// Opt describes the functional option pattern for the md5crypt.Hasher.
type Opt func(h *Hasher) (err error)

// WithVariant is used to configure the md5crypt.Variant of the resulting md5crypt.Digest.
// Default is md5crypt.VariantStandard.
func WithVariant(variant Variant) Opt {
	return func(h *Hasher) (err error) {
		switch variant {
		case VariantNone:
			return nil
		case VariantStandard, VariantSun:
			h.variant = variant

			return nil
		default:
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf("%w: variant '%d' is invalid", algorithm.ErrParameterInvalid, variant))
		}
	}
}

// WithVariantName uses the variant name or identifier to configure the md5crypt.Variant of the resulting md5crypt.Digest.
// Default is md5crypt.VariantStandard.
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

// WithIterations sets the iterations parameter of the resulting md5crypt.Digest. Only valid for the Sun variant. This
// is encoded in the hash with the 'iterations' parameter.
// Minimum is 0, Maximum is 4294967295. Default is 34000.
func WithIterations(iterations int) Opt {
	return func(h *Hasher) (err error) {
		if iterations < IterationsMin || iterations > IterationsMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "iterations", IterationsMin, "", IterationsMax, iterations))
		}

		h.iterations = iterations

		return nil
	}
}

// WithRounds is an alias for md5crypt.WithIterations.
func WithRounds(rounds int) Opt {
	return WithIterations(rounds)
}

// WithSaltLength adjusts the salt size (in bytes) of the resulting md5crypt.Digest.
// Minimum is 1, Maximum is 8. Default is 8.
func WithSaltLength(bytes int) Opt {
	return func(h *Hasher) (err error) {
		if bytes < SaltLengthMin || bytes > SaltLengthMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "salt size", SaltLengthMin, "", SaltLengthMax, bytes))
		}

		h.bytesSalt = bytes

		return nil
	}
}
