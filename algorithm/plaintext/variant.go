package plaintext

import (
	"github.com/go-crypt/crypt/internal/encoding"
)

// NewVariant converts an identifier string to a Variant.
func NewVariant(identifier string) (variant Variant) {
	switch identifier {
	case AlgIdentifierPlainText:
		return VariantPlainText
	case AlgIdentifierBase64:
		return VariantBase64
	default:
		return VariantNone
	}
}

// Variant is a variant of the Digest.
type Variant int

const (
	// VariantNone is a variant of the Digest which is unknown.
	VariantNone Variant = iota

	// VariantPlainText is a variant of the Digest which stores the key as plain text.
	VariantPlainText

	// VariantBase64 is a variant of the Digest which stores the key as a base64 string.
	VariantBase64
)

// Prefix returns the Variant prefix identifier.
func (v Variant) Prefix() (prefix string) {
	switch v {
	case VariantPlainText:
		return AlgIdentifierPlainText
	case VariantBase64:
		return AlgIdentifierBase64
	default:
		return
	}
}

// Decode performs the decode operation for this Variant.
func (v Variant) Decode(src string) (dst []byte, err error) {
	switch v {
	case VariantBase64:
		return encoding.Base64RawAdaptedEncoding.DecodeString(src)
	default:
		return []byte(src), nil
	}
}

// Encode performs the encode operation for this Variant.
func (v Variant) Encode(src []byte) (dst string) {
	switch v {
	case VariantBase64:
		return encoding.Base64RawAdaptedEncoding.EncodeToString(src)
	default:
		return string(src)
	}
}
