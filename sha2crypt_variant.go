package crypt

import (
	"crypto/sha256"
	"crypto/sha512"
)

// NewSHA2CryptVariant converts an identifier string to a SHA2CryptVariant.
func NewSHA2CryptVariant(identifier string) SHA2CryptVariant {
	switch identifier {
	case AlgorithmPrefixSHA256:
		return SHA2CryptVariantSHA256
	case AlgorithmPrefixSHA512:
		return SHA2CryptVariantSHA512
	default:
		return SHA2CryptVariantNone
	}
}

// SHA2CryptVariant is a variant of the SHA2CryptDigest.
type SHA2CryptVariant int

const (
	// SHA2CryptVariantNone is a variant of the SHA2CryptDigest which is unknown.
	SHA2CryptVariantNone SHA2CryptVariant = iota

	// SHA2CryptVariantSHA256 is a variant of the SHA2CryptDigest which uses SHA-256.
	SHA2CryptVariantSHA256

	// SHA2CryptVariantSHA512 is a variant of the SHA2CryptDigest which uses SHA-512.
	SHA2CryptVariantSHA512
)

// Prefix returns the SHA2CryptVariant prefix identifier.
func (v SHA2CryptVariant) Prefix() (prefix string) {
	switch v {
	case SHA2CryptVariantSHA256:
		return AlgorithmPrefixSHA256
	case SHA2CryptVariantSHA512:
		return AlgorithmPrefixSHA512
	default:
		return
	}
}

// Name returns the SHA2CryptVariant name.
func (v SHA2CryptVariant) Name() (s string) {
	switch v {
	case SHA2CryptVariantSHA256:
		return "sha256"
	case SHA2CryptVariantSHA512:
		return "sha512"
	default:
		return
	}
}

// HashFunc returns the internal HMAC HashFunc.
func (v SHA2CryptVariant) HashFunc() HashFunc {
	switch v {
	case SHA2CryptVariantSHA256:
		return sha256.New
	case SHA2CryptVariantSHA512:
		return sha512.New
	default:
		return nil
	}
}
