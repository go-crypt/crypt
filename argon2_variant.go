package crypt

import (
	"github.com/go-crypt/x/argon2"
)

// NewArgon2Variant converts an identifier string to a Argon2Variant.
func NewArgon2Variant(identifier string) (variant Argon2Variant) {
	switch identifier {
	case AlgorithmPrefixArgon2id:
		return Argon2VariantID
	case AlgorithmPrefixArgon2i:
		return Argon2VariantI
	case AlgorithmPrefixArgon2d:
		return Argon2VariantD
	default:
		return Argon2VariantNone
	}
}

// Argon2Variant is a variant of the Argon2Digest.
type Argon2Variant int

const (
	// Argon2VariantNone is a variant of the Argon2Digest which is unknown.
	Argon2VariantNone Argon2Variant = iota

	// Argon2VariantD is the argon2d variant of the Argon2Digest.
	Argon2VariantD

	// Argon2VariantI is the argon2i variant of the Argon2Digest.
	Argon2VariantI

	// Argon2VariantID is the argon2id variant of the Argon2Digest.
	Argon2VariantID
)

// Prefix returns the Argon2Variant prefix identifier.
func (v Argon2Variant) Prefix() (prefix string) {
	switch v {
	case Argon2VariantID:
		return AlgorithmPrefixArgon2id
	case Argon2VariantI:
		return AlgorithmPrefixArgon2i
	case Argon2VariantD:
		return AlgorithmPrefixArgon2d
	default:
		return
	}
}

// KeyFunc returns the KeyFunc of this Argon2Variant.
func (v Argon2Variant) KeyFunc() argon2.KeyFunc {
	switch v {
	case Argon2VariantI:
		return argon2.IKey
	case Argon2VariantD:
		return argon2.DKey
	case Argon2VariantID:
		return argon2.IDKey
	default:
		return nil
	}
}
