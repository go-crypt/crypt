package crypt

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

func NewPBKDF2Variant(s string) (variant PBKDF2Variant) {
	switch s {
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

type PBKDF2Variant int

const (
	PBKDF2VariantNone PBKDF2Variant = iota
	PBKDF2VariantSHA1
	PBKDF2VariantSHA224
	PBKDF2VariantSHA256
	PBKDF2VariantSHA384
	PBKDF2VariantSHA512
)

func (v PBKDF2Variant) String() (s string) {
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
		return ""
	}
}

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
