package sha2crypt

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// Opt describes the functional option pattern for the scrypt.Hasher.
type Opt func(h *Hasher) (err error)

// WithVariant configures the Variant.
func WithVariant(variant Variant) Opt {
	return func(h *Hasher) (err error) {
		switch variant {
		case VariantNone:
			return nil
		case VariantSHA256, VariantSHA512:
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

// WithSHA256 adjusts this Hasher to utilize the SHA256 hash.Hash.
func WithSHA256() Opt {
	return func(h *Hasher) (err error) {
		h.variant = VariantSHA256

		return nil
	}
}

// WithSHA512 adjusts this Hasher to utilize the SHA512 hash.Hash.
func WithSHA512() Opt {
	return func(h *Hasher) (err error) {
		h.variant = VariantSHA512

		return nil
	}
}

// WithRounds sets the rounds parameter of the resulting Digest. Minimum 1000, Maximum 999999999. Default is 1000000.
func WithRounds(rounds int) Opt {
	return func(h *Hasher) (err error) {
		if rounds < IterationsMin || rounds > IterationsMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "rounds", IterationsMin, "", IterationsMax, rounds))
		}

		h.rounds = rounds

		return nil
	}
}

// WithSaltLength adjusts the salt size (in bytes) of the resulting Digest. Minimum 1, Maximum 16. Default is 16.
func WithSaltLength(bytes int) Opt {
	return func(h *Hasher) (err error) {
		if bytes < SaltSizeMin || bytes > SaltSizeMax {
			return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "salt length", SaltSizeMin, "", SaltSizeMax, bytes))
		}

		h.bytesSalt = bytes

		return nil
	}
}
