package crypt

import (
	"fmt"

	"github.com/go-crypt/x/bcrypt"
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

	unsafe bool
}

func (h *BcryptHash) WithVariant(variant BcryptVariant) *BcryptHash {
	h.variant = variant

	return h
}

// WithoutValidation disables the validation and allows potentially unsafe values. Use at your own risk.
func (h *BcryptHash) WithoutValidation() *BcryptHash {
	h.unsafe = true

	return h
}

// WithCost sets the cost parameter of the resulting Bcrypt hash. Default is 12.
func (h *BcryptHash) WithCost(cost int) *BcryptHash {
	h.cost = cost

	return h
}

// Hash performs the hashing operation and returns either a Digest or an error.
func (h *BcryptHash) Hash(password string) (digest Digest, err error) {
	var salt []byte

	if salt, err = randomBytes(defaultSaltSize); err != nil {
		return nil, fmt.Errorf("bcrypt hashing error: %w: %v", ErrSaltReadRandomBytes, err)
	}

	return h.hashWithSalt(password, salt)
}

// HashWithSalt overloads the Hash method allowing the user to provide a salt. It's recommended instead to configure the
// salt size and let this be a random value generated using crypto/rand.
func (h *BcryptHash) HashWithSalt(password, salt string) (digest Digest, err error) {
	var saltBytes []byte

	if saltBytes, err = bcrypt.Base64Decode([]byte(salt)); err != nil {
		return nil, fmt.Errorf("bcrypt hashing error: %w: %v", ErrSaltEncoding, err)
	}

	return h.hashWithSalt(password, saltBytes)
}

func (h *BcryptHash) hashWithSalt(password string, salt []byte) (digest Digest, err error) {
	h.setDefaults()

	if err = h.validate(); err != nil {
		return nil, err
	}

	d := &BcryptDigest{
		variant: h.variant,
		cost:    h.cost,
		salt:    salt,
	}

	if d.variant == BcryptVariantNone {
		d.variant = BcryptVariantStandard
	}

	if !h.unsafe {
		if len(salt) != defaultSaltSize {
			return nil, fmt.Errorf("bcrypt hashing error: %w: salt size must be 16 bytes but it's %d bytes", ErrSaltInvalid, len(salt))
		}

		passwordMaxLen := d.variant.PasswordMaxLength()

		if passwordMaxLen != -1 && len(password) > passwordMaxLen {
			return nil, fmt.Errorf("bcrypt hashing error: %w: password must be %d bytes or less but it's %d bytes", ErrPasswordInvalid, passwordMaxLen, len(password))
		}
	}

	if d.key, err = bcrypt.Key(d.variant.EncodeInput([]byte(password), salt), salt, d.cost); err != nil {
		return nil, fmt.Errorf("bcrypt hashing error: %w: %v", ErrKeyDerivation, err)
	}

	return d, nil
}

// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (h *BcryptHash) MustHash(password string) (digest Digest) {
	var err error

	if digest, err = h.Hash(password); err != nil {
		panic(err)
	}

	return digest
}

// Validate checks the settings/parameters for this Hash and returns an error.
func (h *BcryptHash) Validate() (err error) {
	return h.validate()
}

func (h *BcryptHash) validate() (err error) {
	h.setDefaults()

	if h.unsafe {
		return nil
	}

	if h.cost > bcryptCostMin {
		return fmt.Errorf("bcrypt validation error: %w: cost must be more than %d but is %d", ErrParameterInvalid, bcryptCostMin, h.cost)
	}

	return nil
}

func (h *BcryptHash) setDefaults() {
	switch h.variant {
	case BcryptVariantNone:
		h.variant = bcryptVariantDefault
	case BcryptVariantStandard, BcryptVariantSHA256:
		break
	default:
		h.variant = bcryptVariantDefault
	}

	if h.cost <= 0 {
		h.cost = bcryptCostDefault
	}
}
