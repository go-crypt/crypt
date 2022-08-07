package crypt

import (
	"fmt"

	"github.com/go-crypt/x/scrypt"
)

// NewScryptHash returns a *ScryptHash without any settings configured.
func NewScryptHash() *ScryptHash {
	return &ScryptHash{}
}

// ScryptHash is a Hash for scrypt which provides a builder design pattern.
type ScryptHash struct {
	ln, r, k, p, bytesSalt int

	defaults, unsafe bool
}

// WithKeySize adjusts the key size of the resulting Scrypt hash. Default is 32.
func (h *ScryptHash) WithKeySize(size int) *ScryptHash {
	h.k = size

	return h
}

// WithSaltSize adjusts the salt size of the resulting Scrypt hash. Default is 16.
func (h *ScryptHash) WithSaltSize(size int) *ScryptHash {
	h.bytesSalt = size

	return h
}

// WithLN sets the ln parameter (logN) of the resulting Scrypt hash. Default is 16.
func (h *ScryptHash) WithLN(rounds int) *ScryptHash {
	h.ln = rounds

	return h
}

// WithR sets the r parameter (block size) of the resulting Scrypt hash. Default is 8.
func (h *ScryptHash) WithR(blockSize int) *ScryptHash {
	h.r = blockSize

	return h
}

// WithP sets the p parameter (parallelism) of the resulting Scrypt hash. Default is 1.
func (h *ScryptHash) WithP(parallelism int) *ScryptHash {
	h.p = parallelism

	return h
}

// Hash performs the hashing operation and returns either a Digest or an error.
func (h *ScryptHash) Hash(password string) (digest Digest, err error) {
	h.setDefaults()

	var salt []byte

	if salt, err = randomBytes(h.bytesSalt); err != nil {
		return nil, fmt.Errorf("scrypt hashing error: %w: %v", ErrSaltReadRandomBytes, err)
	}

	return h.hashWithSalt(password, salt)
}

// HashWithSalt overloads the Hash method allowing the user to provide a salt. It's recommended instead to configure the
// salt size and let this be a random value generated using crypto/rand.
func (h *ScryptHash) HashWithSalt(password, salt string) (digest Digest, err error) {
	var saltBytes []byte

	if saltBytes, err = h.validateSalt(salt); err != nil {
		return nil, err
	}

	return h.hashWithSalt(password, saltBytes)
}

func (h *ScryptHash) hashWithSalt(password string, salt []byte) (digest Digest, err error) {
	if err = h.validate(); err != nil {
		return nil, err
	}

	d := &ScryptDigest{
		ln:   h.ln,
		r:    h.r,
		p:    h.p,
		salt: salt,
	}

	if d.key, err = scrypt.Key([]byte(password), d.salt, d.n(), d.r, d.p, h.k); err != nil {
		return nil, fmt.Errorf("scrypt hashing error: %w: %v", ErrKeyDerivation, err)
	}

	return d, nil
}

// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (h *ScryptHash) MustHash(password string) (digest Digest) {
	var err error

	if digest, err = h.Hash(password); err != nil {
		panic(err)
	}

	return digest
}

// Validate checks the settings/parameters for this Hash and returns an error.
func (h *ScryptHash) Validate() (err error) {
	return h.validate()
}

func (h *ScryptHash) validate() (err error) {
	h.setDefaults()

	if h.unsafe {
		return nil
	}

	return nil
}

func (h *ScryptHash) validateSalt(salt string) (saltBytes []byte, err error) {
	if saltBytes, err = b64rs.DecodeString(salt); err != nil {
		return nil, fmt.Errorf("scrypt validation error: %w: %v", ErrSaltEncoding, err)
	}

	return saltBytes, nil
}

func (h *ScryptHash) setDefaults() {
	if h.defaults {
		return
	}

	h.defaults = true

	if h.ln <= 0 {
		h.ln = scryptRoundsDefault
	}

	if h.r <= 0 {
		h.r = scryptBlockSizeDefault
	}

	if h.p <= 0 {
		h.p = scryptParallelismDefault
	}

	if h.k == 0 {
		h.k = defaultKeySize
	}
}
