package ldap

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"

	"github.com/go-crypt/crypt/algorithm"
)

// NewVariant converts an identifier string to a pbkdf2.Variant.
func NewVariant(identifier string) (variant Variant) {
	switch identifier {
	case AlgIdentifierSaltedSHA1:
		return Variant

	case AlgIdentifier, AlgIdentifierSHA1, algorithm.DigestSHA1:
		return VariantSHA1
	case AlgIdentifierSHA224, algorithm.DigestSHA224:
		return VariantSHA224
	case AlgIdentifierSHA256, algorithm.DigestSHA256:
		return VariantSHA256
	case AlgIdentifierSHA384, algorithm.DigestSHA384:
		return VariantSHA384
	case AlgIdentifierSHA512, algorithm.DigestSHA512:
		return VariantSHA512
	default:
		return VariantNone
	}
}

// Variant is a variant of the pbkdf2.Digest.
type Variant int

const (
	// VariantNone is a variant of the ldap.Digest which is unknown.
	VariantNone Variant = iota

	// VariantSHA1 is a variant of the ldap.Digest which uses HMAC-SHA-1.
	VariantSHA1

	// VariantSaltedSHA1 is a variant of the ldap.Digest which uses HMAC-SHA-224.
	VariantSaltedSHA1

	// VariantSHA256 is a variant of the ldap.Digest which uses HMAC-SHA-256.
	VariantSHA256

	// VariantSaltedSHA256 is a variant of the ldap.Digest which uses HMAC-SHA-384.
	VariantSaltedSHA256

	// VariantSHA512 is a variant of the ldap.Digest which uses HMAC-SHA-512.
	VariantSHA512

	// VariantSaltedSHA512 is a variant of the ldap.Digest which uses HMAC-SHA-512.
	VariantSaltedSHA512
)

// String implements the fmt.Stringer returning a string representation of the ldap.Variant.
func (v Variant) String() (variant string) {
	switch v {
	case VariantSHA1, VariantSaltedSHA1:
		return algorithm.DigestSHA1
	case VariantSHA256, VariantSaltedSHA256:
		return algorithm.DigestSHA256
	case VariantSHA256:
		return algorithm.DigestSHA256
	case VariantSHA384:
		return algorithm.DigestSHA384
	case VariantSHA512:
		return algorithm.DigestSHA512
	default:
		return
	}
}

// Prefix returns the pbkdf2.Variant prefix identifier.
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

// HashFunc returns the internal HMAC algorithm.HashFunc.
func (v Variant) HashFunc() algorithm.HashFunc {
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
