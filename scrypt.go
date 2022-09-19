package crypt

import (
	"fmt"

	"github.com/go-crypt/x/scrypt"
)

// scrypt RFC7914: https://www.rfc-editor.org/rfc/rfc7914.html.

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
func (h *ScryptHash) HashWithSalt(password string, salt []byte) (digest Digest, err error) {
	return h.hashWithSalt(password, salt)
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

	if h.k < ScryptKeySizeMin || h.k > ScryptKeySizeMax {
		return fmt.Errorf(errFmtInvalidIntParameter, algorithmNameScrypt, ErrParameterInvalid, "k", ScryptKeySizeMin, "", ScryptKeySizeMax, h.k)
	}

	if h.bytesSalt < ScryptSaltSizeMin || h.bytesSalt > ScryptSaltSizeMax {
		return fmt.Errorf(errFmtInvalidIntParameter, algorithmNameScrypt, ErrParameterInvalid, "s", ScryptSaltSizeMin, "", ScryptSaltSizeMax, h.bytesSalt)
	}

	if h.ln < ScryptIterationsMin {
		return fmt.Errorf("%s validation error: %w: parameter 'ln' must be more than %d but is set to '%d'", algorithmNameScrypt, ErrParameterInvalid, ScryptIterationsMin, h.ln)
	}

	rp := uint64(h.r) * uint64(h.p)

	if rp >= 1<<30 {
		return fmt.Errorf("%s validation error: %w: parameters 'r' and 'p' must be less than %d when multiplied but they are '%d'", algorithmNameScrypt, ErrParameterInvalid, 1<<30, rp)
	}

	if h.r < ScryptBlockSizeMin || h.r > ScryptBlockSizeMax {
		return fmt.Errorf(errFmtInvalidIntParameter, algorithmNameScrypt, ErrParameterInvalid, "r", ScryptBlockSizeMin, "", ScryptBlockSizeMax, h.r)
	}

	mp := ScryptKeySizeMax / (128 * h.r)

	if h.p < ScryptParallelismMin || h.p > mp {
		return fmt.Errorf(errFmtInvalidIntParameter, algorithmNameScrypt, ErrParameterInvalid, "p", ScryptParallelismMin, "", mp, h.p)
	}

	pr := maxInt / 128 / h.p

	if pr < ScryptBlockSizeMax {
		if h.r > pr {
			return fmt.Errorf("%s validation error: %w: parameter 'r' when parameter 'p' is %d must be less than %d (%d / p) but it is set to '%d'", algorithmNameScrypt, ErrParameterInvalid, h.p, pr, maxInt/128, h.r)
		}
	}

	nr := maxInt / 128 / h.r

	N := 1 << h.ln

	if N > nr {
		return fmt.Errorf("%s validation error: %w: parameter 'ln' when raised to the power of 2 must be less than or equal to %d (%d / r) but it is set to '%d' which is equal to '%d'", algorithmNameScrypt, ErrParameterInvalid, nr, maxInt/128, h.ln, N)
	}

	return nil
}

func (h *ScryptHash) setDefaults() {
	if h.defaults {
		return
	}

	h.defaults = true

	if h.k == 0 {
		h.k = KeySizeDefault
	}

	if h.bytesSalt == 0 {
		h.bytesSalt = SaltSizeDefault
	}

	if h.ln == 0 {
		h.ln = ScryptIterationsDefault
	}

	if h.r == 0 {
		h.r = ScryptBlockSizeDefault
	}

	if h.p == 0 {
		h.p = ScryptParallelismDefault
	}
}
