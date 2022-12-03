package shacrypt

import (
	"fmt"

	xcrypt "github.com/go-crypt/x/crypt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/random"
)

// New returns a *Hasher without any settings configured. This defaults to a SHA512 hash.Hash
// with 1000000 rounds. These settings can be overridden with the methods with the With prefix.
func New(opts ...Opt) (hasher *Hasher, err error) {
	hasher = &Hasher{}

	if err = hasher.WithOptions(
		WithVariant(VariantSHA512),
		WithRounds(VariantSHA512.DefaultRounds()),
	); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(opts...); err != nil {
		return nil, err
	}

	return hasher, nil
}

// Hasher is a algorithm.Hash for SHA2Crypt which can be initialized via New using a functional options pattern.
type Hasher struct {
	variant Variant

	rounds, bytesSalt int

	defaults bool
}

// NewSHA256 returns a *Hasher with the SHA256 hash.Hash which defaults to 1000000 rounds. These
// settings can be overridden with the methods with the With prefix.
func NewSHA256() (hasher *Hasher, err error) {
	return New(
		WithVariant(VariantSHA256),
		WithRounds(VariantSHA256.DefaultRounds()),
	)
}

// NewSHA512 returns a *Hasher with the SHA512 hash.Hash which defaults to 1000000 rounds. These
// settings can be overridden with the methods with the With prefix.
func NewSHA512() (hasher *Hasher, err error) {
	return New(
		WithVariant(VariantSHA512),
		WithRounds(VariantSHA512.DefaultRounds()),
	)
}

// WithOptions defines the options for this scrypt.Hasher.
func (h *Hasher) WithOptions(opts ...Opt) (err error) {
	for _, opt := range opts {
		if err = opt(h); err != nil {
			return err
		}
	}

	return nil
}

// Hash performs the hashing operation and returns either a Digest or an error.
func (h *Hasher) Hash(password string) (digest algorithm.Digest, err error) {
	if digest, err = h.hash(password); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

func (h *Hasher) hash(password string) (digest algorithm.Digest, err error) {
	h.setDefaults()

	var salt []byte

	if salt, err = random.CharSetBytes(h.bytesSalt, SaltCharSet); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrSaltReadRandomBytes, err)
	}

	return h.hashWithSalt(password, salt)
}

// HashWithSalt overloads the Hash method allowing the user to provide a salt. It's recommended instead to configure the
// salt size and let this be a random value generated using crypto/rand.
func (h *Hasher) HashWithSalt(password string, salt []byte) (digest algorithm.Digest, err error) {
	if digest, err = h.hashWithSalt(password, salt); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

func (h *Hasher) hashWithSalt(password string, salt []byte) (digest algorithm.Digest, err error) {
	if err = h.validateSalt(salt); err != nil {
		return nil, err
	}

	d := &Digest{
		variant: h.variant,
		rounds:  h.rounds,
		salt:    salt,
	}

	d.key = xcrypt.KeySHACrypt(d.variant.HashFunc(), []byte(password), d.salt, d.rounds)

	return d, nil
}

// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (h *Hasher) MustHash(password string) (digest algorithm.Digest) {
	var err error

	if digest, err = h.Hash(password); err != nil {
		panic(err)
	}

	return digest
}

// Validate checks the settings/parameters for this Hash and returns an error.
func (h *Hasher) Validate() (err error) {
	if err = h.validate(); err != nil {
		return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, err)
	}

	return nil
}

func (h *Hasher) validate() (err error) {
	h.setDefaults()

	return nil
}

func (h *Hasher) validateSalt(salt []byte) (err error) {
	if len(salt) < SaltSizeMin || len(salt) > SaltSizeMax {
		return fmt.Errorf("%w: salt must be between %d and %d bytes but is %d bytes", algorithm.ErrSaltInvalid, SaltSizeMin, SaltSizeMax, len(salt))
	}

	return nil
}

func (h *Hasher) setDefaults() {
	if h.defaults {
		return
	}

	h.defaults = true

	if h.bytesSalt == 0 {
		h.bytesSalt = algorithm.SaltSizeDefault
	}

	switch h.variant {
	case VariantNone:
		h.variant = VariantSHA512
	case VariantSHA256, VariantSHA512:
		break
	default:
		h.variant = VariantSHA512
	}

	if h.rounds == 0 {
		h.rounds = h.variant.DefaultRounds()
	}
}
