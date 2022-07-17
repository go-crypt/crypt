package crypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/go-crypt/x/bcrypt"
)

// NewBcryptVariant converts an identifier string to a Argon2Variant.
func NewBcryptVariant(identifier string) (variant BcryptVariant) {
	switch identifier {
	case AlgorithmPrefixBcrypt, algorithmPrefixBcryptA, algorithmPrefixBcryptY, algorithmPrefixBcryptX:
		return BcryptVariantStandard
	case AlgorithmPrefixBcryptSHA256:
		return BcryptVariantSHA256
	default:
		return BcryptVariantNone
	}
}

// BcryptVariant is a variant of the Argon2Digest.
type BcryptVariant int

const (
	// BcryptVariantNone is a variant of the BcryptDigest which is unknown.
	BcryptVariantNone BcryptVariant = iota

	// BcryptVariantStandard is the standard variant of BcryptDigest.
	BcryptVariantStandard

	// BcryptVariantSHA256 is the variant of BcryptDigest which hashes the password with SHA-256.
	BcryptVariantSHA256
)

// PasswordMaxLength returns -1 if the variant has no max length, otherwise returns the maximum password length.
func (v BcryptVariant) PasswordMaxLength() int {
	switch v {
	case BcryptVariantSHA256:
		return -1
	default:
		return bcryptPasswordMaxLength
	}
}

// Prefix returns the Argon2Variant prefix identifier.
func (v BcryptVariant) Prefix() (prefix string) {
	switch v {
	case BcryptVariantStandard:
		return AlgorithmPrefixBcrypt
	case BcryptVariantSHA256:
		return AlgorithmPrefixBcryptSHA256
	default:
		return
	}
}

// Encode formats the variant encoded Digest.
func (v BcryptVariant) Encode(cost int, version string, salt, key []byte) (f string) {
	switch v {
	case BcryptVariantStandard:
		return fmt.Sprintf(StorageFormatBcrypt, version, cost, salt, key)
	case BcryptVariantSHA256:
		return fmt.Sprintf(StorageFormatBcryptSHA256, v.Prefix(), version, cost, salt, key)
	default:
		return
	}
}

// EncodeInput returns the appropriate algorithm input.
func (v BcryptVariant) EncodeInput(src, salt []byte) (dst []byte) {
	switch v {
	case BcryptVariantSHA256:
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
