package scrypt

import (
	"github.com/go-crypt/x/scrypt"
	"github.com/go-crypt/x/yescrypt"
)

// NewVariant converts an identifier string to a scrypt.Variant.
func NewVariant(identifier string) (variant Variant) {
	switch identifier {
	case AlgIdentifier:
		return VariantScrypt
	case AlgIdentifierYeScrypt:
		return VariantYeScrypt
	default:
		return VariantNone
	}
}

// Variant is a variant of the scrypt.Digest.
type Variant int

const (
	// VariantNone is the default variant of Scrypt.
	VariantNone Variant = iota

	VariantScrypt

	VariantYeScrypt
)

// String implements the fmt.Stringer returning a string representation of the scrypt.Variant.
func (v Variant) String() (variant string) {
	switch v {
	case VariantScrypt:
		return AlgIdentifier
	case VariantYeScrypt:
		return AlgIdentifierYeScrypt
	default:
		return
	}
}

// Prefix returns the scrypt.Variant prefix identifier.
func (v Variant) Prefix() (prefix string) {
	return v.String()
}

// KeyFunc returns the internal HMAC algorithm.HashFunc.
func (v Variant) KeyFunc() KeyFunc {
	switch v {
	case VariantScrypt:
		return scrypt.Key
	case VariantYeScrypt:
		return yescrypt.Key
	default:
		return nil
	}
}

// KeyFunc represents the KeyFunc used by scrypt implementations.
type KeyFunc func(password []byte, salt []byte, N int, r int, p int, keyLen int) (key []byte, err error)
