package descrypt

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/descrypt"
	"github.com/go-crypt/crypt/internal/random"
)

// New returns a *descrypt.Hasher with the additional opts applied if any.
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

// Hasher is a crypt.Hash for descrypt which can be initialized via descrypt.New using a functional options pattern.
type Hasher struct {
	d bool
}

// WithOptions applies the provided functional options provided as a descrypt.Opt to the descrypt.Hasher.
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
	if digest, err = h.hash(password); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

// MustHash overloads the Hash method and panics if the error is not nil.
func (h *Hasher) MustHash(password string) (digest algorithm.Digest) {
	var err error

	if digest, err = h.Hash(password); err != nil {
		panic(err)
	}

	return digest
}

// HashWithSalt overloads the Hash method allowing the user to provide a salt.
func (h *Hasher) HashWithSalt(password string, salt []byte) (digest algorithm.Digest, err error) {
	if digest, err = h.hashWithSalt(password, salt); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

// Validate checks the settings/parameters for this descrypt.Hasher and returns an error.
func (h *Hasher) Validate() (err error) {
	return nil
}

func (h *Hasher) hash(password string) (digest algorithm.Digest, err error) {
	var salt []byte

	if salt, err = random.CharSetBytes(SaltLength, SaltCharSet); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrSaltReadRandomBytes, err)
	}

	return h.hashWithSalt(password, salt)
}

func (h *Hasher) hashWithSalt(password string, salt []byte) (digest algorithm.Digest, err error) {
	if s := len(salt); s != SaltLength {
		return nil, fmt.Errorf("%w: salt bytes must have a length of %d but has a length of %d", algorithm.ErrSaltInvalid, SaltLength, s)
	}

	d := &Digest{
		salt: salt,
	}

	d.key = descrypt.Key([]byte(password), d.salt)

	return d, nil
}
