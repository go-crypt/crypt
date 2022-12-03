package bcrypt

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// Opt describes the functional option pattern for the bcrypt.Hasher.
type Opt func(h *Hasher) (err error)

// WithVariant adjusts the variant of the bcrypt.Digest algorithm.
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

// WithVariantName satisfies the argon2.Opt type and sets the variant by name.
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

// WithCost sets the cost parameter of the resulting Bcrypt hash. Default is 12.
func WithCost(cost int) Opt {
	return func(h *Hasher) (err error) {
		if cost < CostMin || cost > CostMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "cost", CostMin, "", CostMax, cost))
		}

		h.cost = cost

		return nil
	}
}
