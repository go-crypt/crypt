package bcrypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/go-crypt/x/bcrypt"
)

// NewVariant converts an identifier string to a Argon2Variant.
func NewVariant(identifier string) (variant Variant) {
	switch identifier {
	case AlgIdentifier, AlgIdentifierVerA, AlgIdentifierVerX, AlgIdentifierVerY, "", "standard", "common":
		return VariantStandard
	case AlgIdentifierVariantSHA256, "sha256":
		return VariantSHA256
	default:
		return VariantNone
	}
}

// Variant is a variant of the Argon2Digest.
type Variant int

const (
	// VariantNone is a variant of the bcrypt.Digest which is unknown.
	VariantNone Variant = iota

	// VariantStandard is the standard variant of bcrypt.Digest.
	VariantStandard

	// VariantSHA256 is the variant of bcrypt.Digest which hashes the password with SHA-256.
	VariantSHA256
)

// PasswordMaxLength returns -1 if the variant has no max length, otherwise returns the maximum password length.
func (v Variant) PasswordMaxLength() int {
	switch v {
	case VariantSHA256:
		return -1
	default:
		return PasswordInputSizeMaximum
	}
}

// Prefix returns the Argon2Variant prefix identifier.
func (v Variant) Prefix() (prefix string) {
	switch v {
	case VariantStandard:
		return AlgIdentifier
	case VariantSHA256:
		return AlgIdentifierVariantSHA256
	default:
		return
	}
}

// Encode formats the variant encoded Digest.
func (v Variant) Encode(cost int, version string, salt, key []byte) (f string) {
	switch v {
	case VariantStandard:
		return fmt.Sprintf(EncodingFmt, version, cost, salt, key)
	case VariantSHA256:
		return fmt.Sprintf(EncodingFmtSHA256, v.Prefix(), version, cost, salt, key)
	default:
		return
	}
}

// EncodeInput returns the appropriate algorithm input.
func (v Variant) EncodeInput(src, salt []byte) (dst []byte) {
	switch v {
	case VariantSHA256:
		h := hmac.New(sha256.New, bcrypt.Base64Encode(salt))
		h.Write(src)

		digest := h.Sum(nil)

		dst = make([]byte, base64.StdEncoding.EncodedLen(len(digest)))

		base64.StdEncoding.Encode(dst, digest)

		return dst
	default:
		return src
	}
}
