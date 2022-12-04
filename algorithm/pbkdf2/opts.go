package pbkdf2

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// Opt describes the functional option pattern for the pbkdf2.Hasher.
type Opt func(h *Hasher) (err error)

// WithVariant configures the pbkdf2.Variant of the resulting pbkdf2.Digest.
// Default is pbkdf2.VariantSHA256.
func WithVariant(variant Variant) Opt {
	return func(h *Hasher) (err error) {
		switch variant {
		case VariantNone:
			return nil
		case VariantSHA1, VariantSHA224, VariantSHA256, VariantSHA384, VariantSHA512:
			h.variant = variant

			return nil
		default:
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf("%w: variant '%d' is invalid", algorithm.ErrParameterInvalid, variant))
		}
	}
}

// WithVariantName uses the variant name or identifier to configure the pbkdf2.Variant of the resulting pbkdf2.Digest.
// Default is pbkdf2.VariantSHA256.
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

// WithIterations sets the iterations parameter of the resulting pbkdf2.Digest.
// Minimum is 100000, Maximum is 2147483647. Default is 29000.
func WithIterations(iterations int) Opt {
	return func(h *Hasher) (err error) {
		if iterations < IterationsMin || iterations > IterationsMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "iterations", IterationsMin, "", IterationsMax, iterations))
		}

		h.iterations = iterations

		return nil
	}
}

// WithKeyLength adjusts the tag length (in bytes) of the resulting pbkdf2.Digest. Default is the output length of the
// HMAC digest. Generally it's NOT recommended to change this value at all and let the default values be applied.
// Longer tag lengths technically reduce security by forcing a longer hash calculation for legitimate users but not
// requiring this for an attacker. In addition most implementations expect the tag length to match the output length of
// the HMAC digest. This option MUST come after a specific pbkdf2.WithVariant.
func WithKeyLength(bytes int) Opt {
	return func(h *Hasher) (err error) {
		if h.variant == VariantNone {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf("tag size must not be set before the variant is set"))
		}

		keySizeMin := h.variant.HashFunc()().Size()

		if bytes < keySizeMin || bytes > KeyLengthMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "tag size", keySizeMin, "", KeyLengthMax, bytes))
		}

		h.bytesKey = bytes

		return nil
	}
}

// WithSaltLength adjusts the salt size (in bytes) of the resulting pbkdf2.Digest.
// Minimum is 8, Maximum is 2147483647. Default is 16.
func WithSaltLength(bytes int) Opt {
	return func(h *Hasher) (err error) {
		if bytes < SaltLengthMin || bytes > SaltLengthMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "salt length", SaltLengthMin, "", SaltLengthMax, bytes))
		}

		h.bytesSalt = bytes

		return nil
	}
}
