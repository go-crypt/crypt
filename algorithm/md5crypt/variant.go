package md5crypt

// NewVariant converts an identifier string to a md5crypt.Variant.
func NewVariant(identifier string) (variant Variant) {
	switch identifier {
	case AlgIdentifier, AlgName, VariantNameStandard, "common":
		return VariantStandard
	case AlgIdentifierVariantSun, VariantNameSun:
		return VariantSun
	default:
		return VariantNone
	}
}

// Variant is a variant of the md5crypt.Digest.
type Variant int

const (
	// VariantNone is a variant of the md5crypt.Digest which is unknown.
	VariantNone Variant = iota

	// VariantStandard is a variant of the md5crypt.Digest which uses the standard md5crypt format.
	VariantStandard

	// VariantSun is a variant of the md5crypt.Digest designed at Sun.
	VariantSun
)

// String implements the fmt.Stringer returning a string representation of the md5crypt.Variant.
func (v Variant) String() (prefix string) {
	switch v {
	case VariantStandard:
		return VariantNameStandard
	case VariantSun:
		return VariantNameSun
	default:
		return
	}
}

// Prefix returns the md5crypt.Variant prefix identifier.
func (v Variant) Prefix() (prefix string) {
	switch v {
	case VariantStandard:
		return AlgIdentifier
	case VariantSun:
		return AlgIdentifierVariantSun
	default:
		return
	}
}
