package crypt

import (
	"github.com/go-crypt/x/argon2"
)

func NewArgon2Variant(s string) (variant Argon2Variant) {
	switch s {
	case AlgorithmPrefixArgon2id:
		return Argon2VariantID
	case AlgorithmPrefixArgon2i:
		return Argon2VariantI
	case AlgorithmPrefixArgon2d:
		return Argon2VariantD
	default:
		return Argon2VariantNone
	}
}

type Argon2Variant int

const (
	Argon2VariantNone Argon2Variant = iota
	Argon2VariantD
	Argon2VariantI
	Argon2VariantID
)

func (v Argon2Variant) String() (s string) {
	switch v {
	case Argon2VariantID:
		return AlgorithmPrefixArgon2id
	case Argon2VariantI:
		return AlgorithmPrefixArgon2i
	case Argon2VariantD:
		return AlgorithmPrefixArgon2d
	default:
		return
	}
}

func (v Argon2Variant) KeyFunc() argon2.KeyFunc {
	switch v {
	case Argon2VariantI:
		return argon2.IKey
	case Argon2VariantD:
		return argon2.DKey
	case Argon2VariantID:
		return argon2.IDKey
	default:
		return nil
	}
}
