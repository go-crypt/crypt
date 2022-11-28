package scrypt

import (
	"fmt"
	"math"

	"github.com/go-crypt/x/scrypt"

	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/internal/random"
)

// scrypt RFC7914: https://www.rfc-editor.org/rfc/rfc7914.html.

// New returns a new scrypt.Hasher with the provided functional options applied.
func New(opts ...Opt) (hasher *Hasher, err error) {
	hasher = &Hasher{}

	if err = hasher.WithOptions(
		WithLN(IterationsDefault),
		WithR(BlockSizeDefault),
		WithP(ParallelismDefault),
		WithKeySize(crypt.KeySizeDefault),
		WithSaltSize(crypt.SaltSizeDefault),
	); err != nil {
		return nil, err
	}

	if err = hasher.WithOptions(opts...); err != nil {
		return nil, err
	}

	return hasher, nil
}

// Hasher is a crypt.Hash for scrypt which can be initialized via New using a functional options pattern.
type Hasher struct {
	ln, r, k, p, bytesSalt int

	defaults, unsafe bool
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
func (h *Hasher) Hash(password string) (digest crypt.Digest, err error) {
	if digest, err = h.hash(password); err != nil {
		return nil, fmt.Errorf(crypt.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

func (h *Hasher) hash(password string) (digest crypt.Digest, err error) {
	h.setDefaults()

	var salt []byte

	if salt, err = random.Bytes(h.bytesSalt); err != nil {
		return nil, fmt.Errorf("%w: %v", crypt.ErrSaltReadRandomBytes, err)
	}

	return h.hashWithSalt(password, salt)
}

// HashWithSalt overloads the Hash method allowing the user to provide a salt. It's recommended instead to configure the
// salt size and let this be a random value generated using crypto/rand.
func (h *Hasher) HashWithSalt(password string, salt []byte) (digest crypt.Digest, err error) {
	if digest, err = h.hashWithSalt(password, salt); err != nil {
		return nil, fmt.Errorf(crypt.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

func (h *Hasher) hashWithSalt(password string, salt []byte) (digest crypt.Digest, err error) {
	if err = h.validate(); err != nil {
		return nil, err
	}

	d := &Digest{
		ln:   h.ln,
		r:    h.r,
		p:    h.p,
		salt: salt,
	}

	if d.key, err = scrypt.Key([]byte(password), d.salt, d.n(), d.r, d.p, h.k); err != nil {
		return nil, fmt.Errorf("%w: %v", crypt.ErrKeyDerivation, err)
	}

	return d, nil
}

// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (h *Hasher) MustHash(password string) (digest crypt.Digest) {
	var err error

	if digest, err = h.Hash(password); err != nil {
		panic(err)
	}

	return digest
}

// Validate checks the settings/parameters for this Hash and returns an error.
func (h *Hasher) Validate() (err error) {
	if err = h.validate(); err != nil {
		return fmt.Errorf(crypt.ErrFmtHasherValidation, AlgName, err)
	}

	return nil
}

func (h *Hasher) validate() (err error) {
	h.setDefaults()

	if h.unsafe {
		return nil
	}

	if h.k < KeySizeMin || h.k > KeySizeMax {
		return fmt.Errorf(crypt.ErrFmtInvalidIntParameter, crypt.ErrParameterInvalid, "k", KeySizeMin, "", KeySizeMax, h.k)
	}

	if h.bytesSalt < SaltSizeMin || h.bytesSalt > SaltSizeMax {
		return fmt.Errorf(crypt.ErrFmtInvalidIntParameter, crypt.ErrParameterInvalid, "s", SaltSizeMin, "", SaltSizeMax, h.bytesSalt)
	}

	if h.ln < IterationsMin {
		return fmt.Errorf("%w: parameter 'ln' must be more than %d but is set to '%d'", crypt.ErrParameterInvalid, IterationsMin, h.ln)
	}

	rp := uint64(h.r) * uint64(h.p)

	if rp >= 1<<30 {
		return fmt.Errorf("%w: parameters 'r' and 'p' must be less than %d when multiplied but they are '%d'", crypt.ErrParameterInvalid, 1<<30, rp)
	}

	if h.r < BlockSizeMin || h.r > BlockSizeMax {
		return fmt.Errorf(crypt.ErrFmtInvalidIntParameter, crypt.ErrParameterInvalid, "r", BlockSizeMin, "", BlockSizeMax, h.r)
	}

	mp := KeySizeMax / (128 * h.r)

	if h.p < ParallelismMin || h.p > mp {
		return fmt.Errorf(crypt.ErrFmtInvalidIntParameter, crypt.ErrParameterInvalid, "p", ParallelismMin, "", mp, h.p)
	}

	pr := math.MaxInt / 128 / h.p

	if pr < BlockSizeMax {
		if h.r > pr {
			return fmt.Errorf("%w: parameter 'r' when parameter 'p' is %d must be less than %d (%d / p) but it is set to '%d'", crypt.ErrParameterInvalid, h.p, pr, math.MaxInt/128, h.r)
		}
	}

	nr := math.MaxInt / 128 / h.r

	N := 1 << h.ln

	if N > nr {
		return fmt.Errorf("%w: parameter 'ln' when raised to the power of 2 must be less than or equal to %d (%d / r) but it is set to '%d' which is equal to '%d'", crypt.ErrParameterInvalid, nr, math.MaxInt/128, h.ln, N)
	}

	return nil
}

func (h *Hasher) setDefaults() {
	if h.defaults {
		return
	}

	h.defaults = true

	if h.k == 0 {
		h.k = crypt.KeySizeDefault
	}

	if h.bytesSalt == 0 {
		h.bytesSalt = crypt.SaltSizeDefault
	}

	if h.ln == 0 {
		h.ln = IterationsDefault
	}

	if h.r == 0 {
		h.r = BlockSizeDefault
	}

	if h.p == 0 {
		h.p = ParallelismDefault
	}
}
