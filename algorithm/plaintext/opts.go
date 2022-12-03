package plaintext

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
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
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf("%w: variant '%d' is invalid", algorithm.ErrParameterInvalid, variant))
		}
	}
}

// WithVariantName uses the variant name set the variant.
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
