package crypt

import (
	"fmt"

	"github.com/go-crypt/x/bcrypt"
)

const (
	hashBcryptDefaultCost = 12
	hashBcryptMinimumCost = 10
)

// NewBcryptHash returns a *BcryptHash without any settings configured.
func NewBcryptHash() *BcryptHash {
	return &BcryptHash{}
}

// NewBcryptSHA256Hash returns a SHA256 variant *BcryptHash without any settings configured.
func NewBcryptSHA256Hash() *BcryptHash {
	return NewBcryptHash().WithVariant(BcryptVariantSHA256)
}

// BcryptHash is a Hash for bcrypt which provides a builder design pattern.
type BcryptHash struct {
	variant BcryptVariant

	cost int
}

func (h *BcryptHash) WithVariant(variant BcryptVariant) *BcryptHash {
	h.variant = variant

	return h
}

// WithCost sets the cost parameter of the resulting Bcrypt hash. Default is 12.
func (h *BcryptHash) WithCost(cost int) *BcryptHash {
	h.cost = cost

	return h
}

func (h *BcryptHash) setDefaults() {
	if h.cost <= 0 {
		h.cost = hashBcryptDefaultCost
	}
}

func (h *BcryptHash) Hash(password string) (digest Digest, err error) {
	var salt []byte

	if salt, err = bcrypt.NewSalt(); err != nil {
		return nil, fmt.Errorf("bcrypt hashing error: %w: %v", ErrReadRandomBytesForSalt, err)
	}

	return h.hashWithSalt(password, salt)
}

func (h *BcryptHash) HashWithSalt(password, salt string) (hashed Digest, err error) {
	var saltBytes []byte

	if saltBytes, err = bcrypt.Base64Decode([]byte(salt)); err != nil {
		return nil, fmt.Errorf("bcrypt hashing error: %w: %v", ErrSaltEncoding, err)
	}

	return h.hashWithSalt(password, saltBytes)
}

func (h *BcryptHash) hashWithSalt(password string, salt []byte) (digest Digest, err error) {
	h.setDefaults()

	d := &BcryptDigest{
		variant: h.variant,
		cost:    h.cost,
		salt:    salt,
	}

	if d.variant == BcryptVariantNone {
		d.variant = BcryptVariantStandard
	}

	if d.key, err = bcrypt.Key(d.variant.EncodeInput([]byte(password), salt), salt, d.cost); err != nil {
		return nil, fmt.Errorf("bcrypt hashing error: %w: %v", ErrKeyDerivation, err)
	}

	return d, nil
}

// MustHash overloads the Digest method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (h *BcryptHash) MustHash(password string) (hashed Digest) {
	var err error

	if hashed, err = h.Hash(password); err != nil {
		panic(err)
	}

	return hashed
}

// Validate checks the settings for this hasher.
func (h *BcryptHash) Validate() (err error) {
	h.setDefaults()

	return nil
}
