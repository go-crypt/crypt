package argon2

import (
	"fmt"
)

// Opt describes the functional option pattern for the argon2.Hasher.
type Opt func(h *Hasher) (err error)

// WithVariant satisfies the argon2.Opt type and sets the variant.
func WithVariant(variant Variant) Opt {
	return func(h *Hasher) (err error) {
		switch variant {
		case VariantNone, VariantI, VariantID, VariantD:
			h.variant = variant

			return nil
		default:
			return fmt.Errorf("argon2 variant error: variant with id '%d' is not valid", variant)
		}
	}
}

// WithVariantName satisfies the argon2.Opt type and sets the variant by name.
func WithVariantName(identifier string) Opt {
	return func(h *Hasher) (err error) {
		variant := NewVariant(identifier)

		if variant == VariantNone {
			return fmt.Errorf("argon2: variant identifier '%s' is not known", identifier)
		}

		h.variant = variant

		return nil
	}
}

// WithVariantI satisfies the argon2.Opt type and sets the variant as argon2.VariantI.
func WithVariantI() Opt {
	return func(h *Hasher) error {
		h.variant = VariantI

		return nil
	}
}

// WithVariantID satisfies the argon2.Opt type and sets the variant as argon2.VariantID.
func WithVariantID() Opt {
	return func(h *Hasher) error {
		h.variant = VariantID

		return nil
	}
}

// WithVariantD satisfies the argon2.Opt type and sets the variant as argon2.VariantD.
func WithVariantD() Opt {
	return func(h *Hasher) error {
		h.variant = VariantD

		return nil
	}
}

// WithP satisfies the argon2.Opt type for the argon2.Hasher and sets input 'p' known as the degree of parallelism.
//
// Degree of parallelism p determines how many independent (but synchronizing) computational chains (lanes) can be run.
// It MUST be an integer value from 1 to 2^(24)-1.
//
// RFC9106 section 3.1 "Argon2 Inputs and Outputs" https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-inputs-and-outputs.
func WithP(p int) Opt {
	return func(h *Hasher) (err error) {
		h.p = p

		return nil
	}
}

// WithParallelism is an alias for WithP.
func WithParallelism(p int) Opt {
	return WithP(p)
}

// WithM satisfies the argon2.Opt type for the argon2.Hasher and sets input 'm' known as the memory size.
//
// Memory size m MUST be an integer number of kibibytes from 8*p to 2^(32)-1. The actual number of blocks is m', which
// is m rounded down to the nearest multiple of 4*p.
//
// RFC9106 section 3.1 "Argon2 Inputs and Outputs" https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-inputs-and-outputs.
func WithM(m int) Opt {
	return func(h *Hasher) (err error) {
		h.m = m

		return nil
	}
}

// WithMemoryInKiB is an alias for WithM.
func WithMemoryInKiB(m int) Opt {
	return WithM(m)
}

// WithT satisfies the argon2.Opt type for the argon2.Hasher and sets input 't' known as the number of passes.
//
// Number of passes t (used to tune the running time independently of the memory size) MUST be an integer number from 1 to 2^(32)-1.
//
// RFC9106 section 3.1 "Argon2 Inputs and Outputs" https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-inputs-and-outputs.
func WithT(t int) Opt {
	return func(h *Hasher) (err error) {
		h.t = t

		return nil
	}
}

// WithIterations is an alias for WithT.
func WithIterations(t int) Opt {
	return WithT(t)
}

// WithK satisfies the argon2.Opt type for the argon2.Hasher and sets input 'T' known as the tag length.
//
// Tag length T MUST be an integer number of bytes from 4 to 2^(32)-1. The Argon2 output, or "tag", is a string T bytes long.
//
// RFC9106 section 3.1 "Argon2 Inputs and Outputs" https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-inputs-and-outputs.
func WithK(k int) Opt {
	return func(h *Hasher) (err error) {
		h.k = k

		return nil
	}
}

// WithTagLength is an alias for WithK.
func WithTagLength(k int) Opt {
	return WithK(k)
}

// WithKeyLength is an alias for WithK.
func WithKeyLength(k int) Opt {
	return WithK(k)
}

// WithS satisfies the argon2.Opt type for the argon2.Hasher and sets the length of input 'S' known as the salt length.
//
// Nonce S, which is a salt for password hashing applications. It MUST have a length not greater than 2^(32)-1 bytes.
// 16 bytes is RECOMMENDED for password hashing. The salt SHOULD be unique for each password.
//
// RFC9106 section 3.1 "Argon2 Inputs and Outputs" https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-inputs-and-outputs.
func WithS(s int) Opt {
	return func(h *Hasher) (err error) {
		h.s = s

		return nil
	}
}

// WithSaltLength is an alias for WithS.
func WithSaltLength(s int) Opt {
	return WithS(s)
}

// WithUnsafe allows several unsafe values.
func WithUnsafe() Opt {
	return func(h *Hasher) (err error) {
		h.unsafe = true

		return nil
	}
}

// WithSafe disallows several unsafe values. This is the default.
func WithSafe() Opt {
	return func(h *Hasher) (err error) {
		h.unsafe = false

		return nil
	}
}

// WithProfileRFC9106Recommended is the recommended standard RFC9106 profile.
//
// RFC9106 section 4.0 "Parameter Choice" https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
func WithProfileRFC9106Recommended() Opt {
	return func(h *Hasher) (err error) {
		ProfileRFC9106Recommended.Hasher().Merge(h)

		return nil
	}
}

// WithProfileRFC9106LowMemory is the recommended low memory RFC9106 profile.
//
// RFC9106 section 4.0 "Parameter Choice" https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
func WithProfileRFC9106LowMemory() Opt {
	return func(h *Hasher) (err error) {
		ProfileRFC9106LowMemory.Hasher().Merge(h)

		return nil
	}
}