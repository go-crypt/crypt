package pbkdf2

import (
	"fmt"
)

// Opt describes the functional option pattern for the pbkdf2.Hasher.
type Opt func(h *Hasher) (err error)

// WithVariant configures the Variant.
func WithVariant(variant Variant) Opt {
	return func(h *Hasher) (err error) {
		switch variant {
		case VariantNone:
			return nil
		case VariantSHA1, VariantSHA224, VariantSHA256, VariantSHA384, VariantSHA512:
			h.variant = variant

			return nil
		default:
			return fmt.Errorf("pbkdf2 variant error: variant with id '%d' is not valid", variant)
		}
	}
}

// WithVariantName uses the variant name set the variant.
func WithVariantName(identifier string) Opt {
	return func(h *Hasher) (err error) {
		variant := NewVariant(identifier)

		if variant == VariantNone {
			return fmt.Errorf("pbkdf2: variant identifier '%s' is not known", identifier)
		}

		h.variant = variant

		return nil
	}
}

// WithoutValidation disables the validation and allows potentially unsafe values. Use at your own risk.
func WithoutValidation() Opt {
	return func(h *Hasher) (err error) {
		h.unsafe = true

		return nil
	}
}

// WithIterations sets the iterations parameter of the resulting Digest. Default is 29000.
func WithIterations(iterations int) Opt {
	return func(h *Hasher) (err error) {
		h.iterations = iterations

		return nil
	}
}

// WithKeyLength adjusts the key size (in bytes) of the resulting Digest. Default is the output length of the
// HMAC digest. Generally it's NOT recommended to change this value at all and let the default values be applied.
// Longer key lengths technically reduce security by forcing a longer hash calculation for legitimate users but not
// requiring this for an attacker. In addition most implementations expect the key length to match the output length of
// the HMAC digest.
func WithKeyLength(bytes int) Opt {
	return func(h *Hasher) (err error) {
		h.bytesKey = bytes

		return nil
	}
}

// WithDefaultKeyLength sets the key length if it's not already set. It's strongly suggested you see WithKeyLength.
func WithDefaultKeyLength(bytes int) Opt {
	return func(h *Hasher) (err error) {
		if h.bytesKey == 0 {
			h.bytesKey = bytes
		}

		return nil
	}
}

// WithSaltLength adjusts the salt size (in bytes) of the resulting Digest. Default is 16.
func WithSaltLength(bytes int) Opt {
	return func(h *Hasher) (err error) {
		h.bytesSalt = bytes

		return nil
	}
}
