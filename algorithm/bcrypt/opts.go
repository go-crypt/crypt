package bcrypt

import (
	"fmt"
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
			return fmt.Errorf("bcrypt variant error: variant with id '%d' is not valid", variant)
		}
	}
}

// WithCost sets the cost parameter of the resulting Bcrypt hash. Default is 12.
func WithCost(cost int) Opt {
	return func(h *Hasher) (err error) {
		h.cost = cost

		return nil
	}
}
