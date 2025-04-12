package scrypt

import (
	"encoding/base64"
	"fmt"

	"github.com/go-crypt/x/scrypt"
	"github.com/go-crypt/x/yescrypt"
)

// NewVariant converts an identifier string to a scrypt.Variant.
func NewVariant(identifier string) (variant Variant) {
	switch identifier {
	case AlgName:
		return VariantScrypt
	case AlgNameYescrypt, AlgIdentifierYescrypt:
		return VariantYescrypt
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

	VariantYescrypt
)

// String implements the fmt.Stringer returning a string representation of the scrypt.Variant.
func (v Variant) String() (variant string) {
	switch v {
	case VariantScrypt:
		return AlgIdentifier
	case VariantYescrypt:
		return AlgIdentifierYescrypt
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
	case VariantYescrypt:
		return yescrypt.Key
	default:
		return nil
	}
}

// Encode formats the variant encoded bcrypt.Digest.
func (v Variant) Encode(ln, r, p int, salt, key []byte) (f string) {
	switch v {
	case VariantScrypt:
		return fmt.Sprintf(EncodingFmt, v.Prefix(), ln, r, p, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	case VariantYescrypt:
		return fmt.Sprintf(EncodingFmtYescrypt, v.Prefix(), yescrypt.EncodeSetting(0, ln, r), yescrypt.Encode64(salt), yescrypt.Encode64(key))
	default:
		return
	}
}

// KeyFunc represents the KeyFunc used by scrypt implementations.
type KeyFunc func(password []byte, salt []byte, N int, r int, p int, keyLen int) (key []byte, err error)
