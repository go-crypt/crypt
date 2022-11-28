package argon2

import (
	"github.com/go-crypt/x/argon2"
)

// NewVariant converts an identifier string to a argon2.Variant.
func NewVariant(identifier string) (variant Variant) {
	switch identifier {
	case AlgIdentifierVariantID:
		return VariantID
	case AlgIdentifierVariantI:
		return VariantI
	case AlgIdentifierVariantD:
		return VariantD
	default:
		return VariantNone
	}
}

// Variant is a variant of the Digest.
type Variant int

const (
	// VariantNone is a variant of the argon2.Digest which is not set.
	VariantNone Variant = iota

	// VariantD is the argon2d variant of the argon2.Digest.
	VariantD

	// VariantI is the argon2i variant of the argon2.Digest.
	VariantI

	// VariantID is the argon2id variant of the argon2.Digest.
	VariantID
)

// String implements the fmt.Stringer returning a string representation of the argon2.Variant.
func (v Variant) String() string {
	return v.Prefix()
}

// Prefix returns the argon2.Variant prefix identifier.
func (v Variant) Prefix() (prefix string) {
	switch v {
	case VariantID:
		return AlgIdentifierVariantID
	case VariantI:
		return AlgIdentifierVariantI
	case VariantD:
		return AlgIdentifierVariantD
	default:
		return
	}
}

// KeyFunc returns the argon2.KeyFunc key derivation function of this argon2.Variant.
func (v Variant) KeyFunc() argon2.KeyFunc {
	switch v {
	case VariantID:
		return argon2.IDKey
	case VariantI:
		return argon2.IKey
	case VariantD:
		return argon2.DKey
	default:
		return nil
	}
}
