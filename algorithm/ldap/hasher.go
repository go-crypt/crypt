package ldap

import (
	"fmt"

	"github.com/go-crypt/x/pbkdf2"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/random"
)

// New returns a *pbkdf2.Hasher with the additional opts applied if any.
func New(opts ...Opt) (hasher *Hasher, err error) {
	hasher = &Hasher{}

	if err = hasher.WithOptions(opts...); err != nil {
		return nil, err
	}

	if err = hasher.Validate(); err != nil {
		return nil, err
	}

	return hasher, nil
}

// NewSHA1 returns a SHA1 variant *pbkdf2.Hasher with the additional opts applied if any.
func NewSHA1(opts ...Opt) (hasher *Hasher, err error) {
	if hasher, err = New(opts...); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(WithVariant(VariantSHA1)); err != nil {
		return nil, err
	}

	return hasher, nil
}

// NewSHA224 returns a SHA224 variant *pbkdf2.Hasher with the additional opts applied if any.
func NewSHA224(opts ...Opt) (hasher *Hasher, err error) {
	if hasher, err = New(opts...); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(WithVariant(VariantSHA224)); err != nil {
		return nil, err
	}

	return hasher, nil
}

// NewSHA256 returns a SHA256 variant *pbkdf2.Hasher with the additional opts applied if any.
func NewSHA256(opts ...Opt) (hasher *Hasher, err error) {
	if hasher, err = New(opts...); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(WithVariant(VariantSHA256)); err != nil {
		return nil, err
	}

	return hasher, nil
}

// NewSHA384 returns a SHA384 variant *pbkdf2.Hasher with the additional opts applied if any.
func NewSHA384(opts ...Opt) (hasher *Hasher, err error) {
	if hasher, err = New(opts...); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(WithVariant(VariantSHA384)); err != nil {
		return nil, err
	}

	return hasher, nil
}

// NewSHA512 returns a SHA512 variant *pbkdf2.Hasher with the additional opts applied if any.
func NewSHA512(opts ...Opt) (hasher *Hasher, err error) {
	if hasher, err = New(opts...); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(WithVariant(VariantSHA512)); err != nil {
		return nil, err
	}

	return hasher, nil
}

// Hasher is a crypt.Hash for PBKDF2 which can be initialized via pbkdf2.New using a functional options pattern.
type Hasher struct {
	variant Variant

	iterations, bytesKey, bytesSalt int

	d bool
}

// WithOptions applies the provided functional options provided as a pbkdf2.Opt to the pbkdf2.Hasher.
func (h *Hasher) WithOptions(opts ...Opt) (err error) {
	for _, opt := range opts {
		if err = opt(h); err != nil {
			return err
		}
	}

	return nil
}

// Hash performs the hashing operation and returns either a algorithm.Digest or an error.
func (h *Hasher) Hash(password string) (digest algorithm.Digest, err error) {
	h.defaults()

	if digest, err = h.hash(password); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

func (h *Hasher) hash(password string) (digest algorithm.Digest, err error) {
	var salt []byte

	if salt, err = random.Bytes(h.bytesSalt); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrSaltReadRandomBytes, err)
	}

	return h.hashWithSalt(password, salt)
}

// HashWithSalt overloads the Hash method allowing the user to provide a salt. It's recommended instead to configure the
// salt size and let this be a random value generated using crypto/rand.
func (h *Hasher) HashWithSalt(password string, salt []byte) (digest algorithm.Digest, err error) {
	h.defaults()

	if digest, err = h.hashWithSalt(password, salt); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

func (h *Hasher) hashWithSalt(password string, salt []byte) (digest algorithm.Digest, err error) {
	if s := len(salt); s > SaltLengthMax || s < SaltLengthMin {
		return nil, fmt.Errorf("%w: salt bytes must have a length of between %d and %d but has a length of %d", algorithm.ErrSaltInvalid, SaltLengthMin, SaltLengthMax, len(salt))
	}

	d := &Digest{
		variant:    h.variant,
		iterations: h.iterations,
		t:          h.bytesKey,
		salt:       salt,
	}

	d.defaults()

	d.key = pbkdf2.Key([]byte(password), d.salt, d.iterations, d.t, d.variant.HashFunc())

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
	h.defaults()

	keyLengthMin := h.variant.HashFunc()().Size()

	if h.bytesKey < keyLengthMin || h.bytesKey > KeyLengthMax {
		return fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "key length", keyLengthMin, "", KeyLengthMax, h.bytesKey)
	}

	return nil
}

func (h *Hasher) defaults() {
	if h.d {
		return
	}

	h.d = true

	if h.variant == VariantNone {
		h.variant = variantDefault
	}

	if h.bytesKey == 0 {
		h.bytesKey = h.variant.HashFunc()().Size()
	}

	if h.bytesSalt < SaltLengthMin {
		h.bytesSalt = algorithm.SaltLengthDefault
	}
}
