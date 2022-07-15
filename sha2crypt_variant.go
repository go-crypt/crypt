package crypt

import (
	"crypto/sha256"
	"crypto/sha512"
)

func NewSHA2CryptVariant(prefix string) SHA2CryptVariant {
	switch prefix {
	case AlgorithmPrefixSHA256:
		return SHA2CryptVariantSHA256
	case AlgorithmPrefixSHA512:
		return SHA2CryptVariantSHA512
	default:
		return SHA2CryptVariantNone
	}
}

type SHA2CryptVariant int

const (
	SHA2CryptVariantNone SHA2CryptVariant = iota
	SHA2CryptVariantSHA256
	SHA2CryptVariantSHA512
)

func (v SHA2CryptVariant) Prefix() (s string) {
	switch v {
	case SHA2CryptVariantSHA256:
		return AlgorithmPrefixSHA256
	case SHA2CryptVariantSHA512:
		return AlgorithmPrefixSHA512
	default:
		return
	}
}

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

func (v SHA2CryptVariant) String() (s string) {
	switch v {
	case SHA2CryptVariantSHA256:
		return "sha256"
	case SHA2CryptVariantSHA512:
		return "sha512"
	default:
		return
	}
}
