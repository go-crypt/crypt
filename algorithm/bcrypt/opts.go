package bcrypt

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// Opt describes the functional option pattern for the bcrypt.Hasher.
type Opt func(h *Hasher) (err error)

// WithVariant is used to configure the bcrypt.Variant of the resulting bcrypt.Digest.
// Default is bcrypt.VariantStandard.
func WithVariant(variant Variant) Opt {
	return func(h *Hasher) (err error) {
		switch variant {
		case VariantNone, VariantStandard, VariantSHA256:
			h.variant = variant

			return nil
		default:
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf("%w: variant '%d' is invalid", algorithm.ErrParameterInvalid, variant))
		}
	}
}

// WithVariantName uses the variant name or identifier to configure the bcrypt.Variant of the resulting bcrypt.Digest.
// Default is bcrypt.VariantStandard.
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

// WithIterations sets the iterations parameter of the resulting bcrypt.Digest.
// Minimum is 10, Maximum is 31. Default is 12.
func WithIterations(iterations int) Opt {
	return func(h *Hasher) (err error) {
		if iterations < IterationsMin || iterations > IterationsMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "iterations", IterationsMin, "", IterationsMax, iterations))
		}

		h.iterations = iterations

		return nil
	}
}

// WithCost is an alias for bcrypt.WithIterations.
func WithCost(iterations int) Opt {
	return WithIterations(iterations)
}
