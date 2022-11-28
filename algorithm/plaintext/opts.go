package plaintext

import (
	"fmt"
)

// Opt describes the functional option pattern for the pbkdf2.Hasher.
type Opt func(h *Hasher) (err error)

// WithVariant adjusts the variant of the bcrypt.Digest algorithm.
func WithVariant(variant Variant) Opt {
	return func(h *Hasher) (err error) {
		switch variant {
		case VariantNone, VariantPlainText, VariantBase64:
			h.variant = variant

			return nil
		default:
			return fmt.Errorf("plaintext variant error: variant with id '%d' is not valid", variant)
		}
	}
}
