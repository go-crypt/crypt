package bcrypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/go-crypt/x/bcrypt"
)

// NewVariant converts an identifier string to a bcrypt.Variant.
func NewVariant(identifier string) (variant Variant) {
	switch identifier {
	case AlgIdentifier, AlgIdentifierVerA, AlgIdentifierVerX, AlgIdentifierVerY, "", VariantNameStandard, "common":
		return VariantStandard
	case AlgIdentifierVariantSHA256, VariantNameSHA256:
		return VariantSHA256
	default:
		return VariantNone
	}
}

// Variant is a variant of the bcrypt.Digest.
type Variant int

const (
	// VariantNone is a variant of the bcrypt.Digest which is unknown.
	VariantNone Variant = iota

	// VariantStandard is the standard variant of bcrypt.Digest.
	VariantStandard

	// VariantSHA256 is the variant of bcrypt.Digest which hashes the password with HMAC-SHA256.
	VariantSHA256
)

// String implements the fmt.Stringer returning a string representation of the bcrypt.Variant.
func (v Variant) String() (name string) {
	switch v {
	case VariantStandard:
		return VariantNameStandard
	case VariantSHA256:
		return VariantNameSHA256
	default:
		return
	}
}

// Prefix returns the bcrypt.Variant prefix identifier.
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

// PasswordMaxLength returns -1 if the variant has no max length, otherwise returns the maximum password length.
func (v Variant) PasswordMaxLength() int {
	switch v {
	case VariantSHA256:
		return -1
	default:
		return PasswordInputSizeMax
	}
}

// Encode formats the variant encoded bcrypt.Digest.
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
