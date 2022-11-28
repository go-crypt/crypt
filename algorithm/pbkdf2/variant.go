package pbkdf2

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"

	"github.com/go-crypt/crypt"
)

// NewVariant converts an identifier string to a Variant.
func NewVariant(identifier string) (variant Variant) {
	switch identifier {
	case AlgIdentifier, AlgIdentifierSHA1, crypt.DigestSHA1:
		return VariantSHA1
	case AlgIdentifierSHA224, crypt.DigestSHA224:
		return VariantSHA224
	case AlgIdentifierSHA256, crypt.DigestSHA256:
		return VariantSHA256
	case AlgIdentifierSHA384, crypt.DigestSHA384:
		return VariantSHA384
	case AlgIdentifierSHA512, crypt.DigestSHA512:
		return VariantSHA512
	default:
		return VariantNone
	}
}

// Variant is a variant of the Digest.
type Variant int

const (
	// VariantNone is a variant of the Digest which is unknown.
	VariantNone Variant = iota

	// VariantSHA1 is a variant of the Digest which uses HMAC-SHA-1.
	VariantSHA1

	// VariantSHA224 is a variant of the Digest which uses HMAC-SHA-224.
	VariantSHA224

	// VariantSHA256 is a variant of the Digest which uses HMAC-SHA-256.
	VariantSHA256

	// VariantSHA384 is a variant of the Digest which uses HMAC-SHA-384.
	VariantSHA384

	// VariantSHA512 is a variant of the Digest which uses HMAC-SHA-512.
	VariantSHA512
)

// Prefix returns the PlainTextVariant prefix identifier.
func (v Variant) Prefix() (prefix string) {
	switch v {
	case VariantSHA1:
		return AlgIdentifier
	case VariantSHA224:
		return AlgIdentifierSHA224
	case VariantSHA256:
		return AlgIdentifierSHA256
	case VariantSHA384:
		return AlgIdentifierSHA384
	case VariantSHA512:
		return AlgIdentifierSHA512
	default:
		return
	}
}

// HashFunc returns the internal HMAC HashFunc.
func (v Variant) HashFunc() crypt.HashFunc {
	switch v {
	case VariantSHA1:
		return sha1.New
	case VariantSHA224:
		return sha256.New224
	case VariantSHA256:
		return sha256.New
	case VariantSHA384:
		return sha512.New384
	case VariantSHA512:
		return sha512.New
	default:
		return nil
	}
}

// DefaultIterations returns the default iterations for a variant.
func (v Variant) DefaultIterations() int {
	switch v {
	case VariantSHA1, VariantSHA224:
		return IterationsDefaultSHA1
	case VariantSHA256, VariantSHA384:
		return IterationsDefaultSHA256
	case VariantSHA512:
		return IterationsDefaultSHA512
	default:
		return IterationsDefaultSHA1
	}
}
