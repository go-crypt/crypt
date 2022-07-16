package crypt

// NewPlainTextVariant converts an identifier string to a PlainTextVariant.
func NewPlainTextVariant(identifier string) (variant PlainTextVariant) {
	switch identifier {
	case AlgorithmPrefixPlainText:
		return PlainTextVariantPlainText
	case AlgorithmPrefixBase64:
		return PlainTextVariantBase64
	default:
		return PlainTextVariantNone
	}
}

// PlainTextVariant is a variant of the PlainTextDigest.
type PlainTextVariant int

const (
	// PlainTextVariantNone is a variant of the PlainTextDigest which is unknown.
	PlainTextVariantNone PlainTextVariant = iota

	// PlainTextVariantPlainText is a variant of the PlainTextDigest which stores the key as plain text.
	PlainTextVariantPlainText

	// PlainTextVariantBase64 is a variant of the PlainTextDigest which stores the key as a base64 string.
	PlainTextVariantBase64
)

// String returns the PlainTextVariant prefix identifier.
func (v PlainTextVariant) String() (s string) {
	switch v {
	case PlainTextVariantPlainText:
		return AlgorithmPrefixPlainText
	case PlainTextVariantBase64:
		return AlgorithmPrefixBase64
	default:
		return ""
	}
}

// Decode performs the decode operation for this PlainTextVariant.
func (v PlainTextVariant) Decode(src string) (dst []byte, err error) {
	switch v {
	case PlainTextVariantBase64:
		return b64ra.DecodeString(src)
	default:
		return []byte(src), nil
	}
}

// Encode performs the encode operation for this PlainTextVariant.
func (v PlainTextVariant) Encode(src []byte) (dst string) {
	switch v {
	case PlainTextVariantBase64:
		return b64ra.EncodeToString(src)
	default:
		return string(src)
	}
}
