package sha2crypt

// Opt describes the functional option pattern for the scrypt.Hasher.
type Opt func(h *Hasher) (err error)

// WithVariant adjusts this Hasher to utilize the provided variant.
func WithVariant(variant Variant) Opt {
	return func(h *Hasher) (err error) {
		h.variant = variant

		return nil
	}
}

// WithSHA256 adjusts this Hasher to utilize the SHA256 hash.Hash.
func WithSHA256() Opt {
	return func(h *Hasher) (err error) {
		h.variant = VariantSHA256

		return nil
	}
}

// WithSHA512 adjusts this Hasher to utilize the SHA512 hash.Hash.
func WithSHA512() Opt {
	return func(h *Hasher) (err error) {
		h.variant = VariantSHA512

		return nil
	}
}

// WithoutValidation disables the validation and allows potentially unsafe values. Use at your own risk.
func WithoutValidation() Opt {
	return func(h *Hasher) (err error) {
		h.unsafe = true

		return nil
	}
}

// WithRounds sets the rounds parameter of the resulting Digest. Default is 1000000.
func WithRounds(rounds int) Opt {
	return func(h *Hasher) (err error) {
		h.rounds = rounds

		return nil
	}
}

// WithSaltLength adjusts the salt size (in bytes) of the resulting Digest. Minimum 1, Maximum 16. Default is
// 16.
func WithSaltLength(bytes int) Opt {
	return func(h *Hasher) (err error) {
		h.bytesSalt = bytes

		return nil
	}
}
