package plaintext

import (
	"github.com/go-crypt/crypt"
)

// New returns a *Hasher without any settings configured.
func New(opts ...Opt) (hasher *Hasher, err error) {
	hasher = &Hasher{}

	if err = hasher.WithOptions(WithVariant(VariantPlainText)); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(opts...); err != nil {
		return nil, err
	}

	return hasher, nil
}

// Hasher is a crypt.Hash for plaintext which can be initialized via New using a functional options pattern.
type Hasher struct {
	variant Variant
}

// WithOptions applies the provided functional options provided as an Opt to the pbkdf2.Hasher.
func (h *Hasher) WithOptions(opts ...Opt) (err error) {
	for _, opt := range opts {
		if err = opt(h); err != nil {
			return err
		}
	}

	return nil
}

// Validate checks the hasher configuration to ensure it's valid. This should be used when the Hash is going to be
// reused and you should use it in conjunction with MustHash.
func (h *Hasher) Validate() (err error) {
	return nil
}

// Hash performs the hashing operation on a password and resets any relevant parameters such as a manually set salt.
// It then returns a Digest and error.
func (h *Hasher) Hash(password string) (hashed crypt.Digest, err error) {
	return &Digest{
		variant: h.variant,
		key:     []byte(password),
	}, nil
}

// HashWithSalt is an overload of Digest that also accepts a salt.
func (h *Hasher) HashWithSalt(password string, _ []byte) (hashed crypt.Digest, err error) {
	return h.Hash(password)
}

// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this method to
// utilize the Validate method first or handle the panic appropriately.
func (h *Hasher) MustHash(password string) (hashed crypt.Digest) {
	if d, err := h.Hash(password); err != nil {
		panic(err)
	} else {
		return d
	}
}
