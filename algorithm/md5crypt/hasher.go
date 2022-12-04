package md5crypt

import (
	"fmt"

	"github.com/go-crypt/x/crypt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/random"
)

// New returns a *md5crypt.Hasher with the additional opts applied if any.
func New(opts ...Opt) (hasher *Hasher, err error) {
	hasher = &Hasher{}

	if err = hasher.WithOptions(opts...); err != nil {
		return nil, err
	}

	return hasher, nil
}

// Hasher is a crypt.Hash for md5crypt which can be initialized via md5crypt.New using a functional options pattern.
type Hasher struct {
	variant Variant

	iterations uint32

	bytesSalt int

	d bool
}

// WithOptions applies the provided functional options provided as a md5crypt.Opt to the md5crypt.Hasher.
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

// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (h *Hasher) MustHash(password string) (digest algorithm.Digest) {
	var err error

	if digest, err = h.Hash(password); err != nil {
		panic(err)
	}

	return digest
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

// Validate checks the settings/parameters for this md5crypt.Hasher and returns an error.
func (h *Hasher) Validate() (err error) {
	h.defaults()

	return nil
}

func (h *Hasher) hash(password string) (digest algorithm.Digest, err error) {
	var salt []byte

	if salt, err = random.CharSetBytes(h.bytesSalt, SaltCharSet); err != nil {
		return nil, fmt.Errorf("%w: %v", algorithm.ErrSaltReadRandomBytes, err)
	}

	return h.hashWithSalt(password, salt)
}

func (h *Hasher) hashWithSalt(password string, salt []byte) (digest algorithm.Digest, err error) {
	if s := len(salt); s > SaltLengthMax || s < SaltLengthMin {
		return nil, fmt.Errorf("%w: salt bytes must have a length of between %d and %d but has a length of %d", algorithm.ErrSaltInvalid, SaltLengthMin, SaltLengthMax, len(salt))
	}

	d := &Digest{
		variant:    h.variant,
		iterations: h.iterations,
		salt:       salt,
	}

	d.defaults()

	switch d.variant {
	case VariantSun:
		d.key = crypt.KeyMD5CryptSun([]byte(password), d.salt, d.iterations)
	default:
		d.key = crypt.KeyMD5Crypt([]byte(password), d.salt)
	}

	return d, nil
}

func (h *Hasher) defaults() {
	if h.d {
		return
	}

	h.d = true

	if h.bytesSalt < SaltLengthMin {
		h.bytesSalt = SaltLengthDefault
	}
}
