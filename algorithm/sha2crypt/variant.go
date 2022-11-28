package sha2crypt

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/go-crypt/crypt/algorithm"
)

// NewVariant converts an identifier string to a Variant.
func NewVariant(identifier string) Variant {
	switch identifier {
	case AlgIdentifierSHA256, algorithm.DigestSHA256:
		return VariantSHA256
	case AlgIdentifierSHA512, algorithm.DigestSHA512:
		return VariantSHA512
	default:
		return VariantSHA512
	}
}

// Variant is a variant of the Digest.
type Variant int

const (
	// VariantNone is a variant of the Digest which is unknown.
	VariantNone Variant = iota

	// VariantSHA256 is a variant of the Digest which uses SHA-256.
	VariantSHA256

	// VariantSHA512 is a variant of the Digest which uses SHA-512.
	VariantSHA512
)

// Prefix returns the Variant prefix identifier.
func (v Variant) Prefix() (prefix string) {
	switch v {
	case VariantSHA256:
		return AlgIdentifierSHA256
	case VariantSHA512:
		return AlgIdentifierSHA512
	default:
		return AlgIdentifierSHA512
	}
}

// Name returns the Variant name.
func (v Variant) Name() (s string) {
	switch v {
	case VariantSHA256:
		return algorithm.DigestSHA256
	case VariantSHA512:
		return algorithm.DigestSHA512
	default:
		return algorithm.DigestSHA512
	}
}

// HashFunc returns the internal HMAC HashFunc.
func (v Variant) HashFunc() algorithm.HashFunc {
	switch v {
	case VariantSHA256:
		return sha256.New
	case VariantSHA512:
		return sha512.New
	default:
		return sha512.New
	}
}

// DefaultRounds returns the default rounds for the particular variant.
func (v Variant) DefaultRounds() int {
	switch v {
	case VariantSHA512:
		return IterationsDefaultSHA512
	default:
		return IterationsDefaultSHA256
	}
}
