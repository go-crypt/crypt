package crypt

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

// NewPBKDF2Variant converts an identifier string to a PBKDF2Variant.
func NewPBKDF2Variant(identifier string) (variant PBKDF2Variant) {
	switch identifier {
	case AlgorithmPrefixPBKDF2, AlgorithmPrefixPBKDF2SHA1:
		return PBKDF2VariantSHA1
	case AlgorithmPrefixPBKDF2SHA224:
		return PBKDF2VariantSHA224
	case AlgorithmPrefixPBKDF2SHA256:
		return PBKDF2VariantSHA256
	case AlgorithmPrefixPBKDF2SHA384:
		return PBKDF2VariantSHA384
	case AlgorithmPrefixPBKDF2SHA512:
		return PBKDF2VariantSHA512
	default:
		return PBKDF2VariantNone
	}
}

// PBKDF2Variant is a variant of the PBKDF2Digest.
type PBKDF2Variant int

const (
	// PBKDF2VariantNone is a variant of the PBKDF2Digest which is unknown.
	PBKDF2VariantNone PBKDF2Variant = iota

	// PBKDF2VariantSHA1 is a variant of the PBKDF2Digest which uses HMAC-SHA-1.
	PBKDF2VariantSHA1

	// PBKDF2VariantSHA224 is a variant of the PBKDF2Digest which uses HMAC-SHA-224.
	PBKDF2VariantSHA224

	// PBKDF2VariantSHA256 is a variant of the PBKDF2Digest which uses HMAC-SHA-256.
	PBKDF2VariantSHA256

	// PBKDF2VariantSHA384 is a variant of the PBKDF2Digest which uses HMAC-SHA-384.
	PBKDF2VariantSHA384

	// PBKDF2VariantSHA512 is a variant of the PBKDF2Digest which uses HMAC-SHA-512.
	PBKDF2VariantSHA512
)

// Prefix returns the PlainTextVariant prefix identifier.
func (v PBKDF2Variant) Prefix() (prefix string) {
	switch v {
	case PBKDF2VariantSHA1:
		return AlgorithmPrefixPBKDF2
	case PBKDF2VariantSHA224:
		return AlgorithmPrefixPBKDF2SHA224
	case PBKDF2VariantSHA256:
		return AlgorithmPrefixPBKDF2SHA256
	case PBKDF2VariantSHA384:
		return AlgorithmPrefixPBKDF2SHA384
	case PBKDF2VariantSHA512:
		return AlgorithmPrefixPBKDF2SHA512
	default:
		return
	}
}

// HashFunc returns the internal HMAC HashFunc.
func (v PBKDF2Variant) HashFunc() HashFunc {
	switch v {
	case PBKDF2VariantSHA1:
		return sha1.New
	case PBKDF2VariantSHA224:
		return sha256.New224
	case PBKDF2VariantSHA256:
		return sha256.New
	case PBKDF2VariantSHA384:
		return sha512.New384
	case PBKDF2VariantSHA512:
		return sha512.New
	default:
		return nil
	}
}
