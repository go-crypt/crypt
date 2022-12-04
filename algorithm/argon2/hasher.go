package argon2

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/internal/random"
)

// New returns a new argon2.Hasher with the provided functional options applied.
func New(opts ...Opt) (hasher *Hasher, err error) {
	hasher = ProfileRFC9106Recommended.Hasher()

	if err = hasher.WithOptions(opts...); err != nil {
		return nil, err
	}

	if err = hasher.Validate(); err != nil {
		return nil, err
	}

	return hasher, nil
}

// Hasher is a crypt.Hash for Argon2 which can be initialized via argon2.New using a functional options pattern.
type Hasher struct {
	variant Variant

	s, k, m, t, p int

	d bool
}

// WithOptions applies the provided functional options provided as an argon2.Opt to the argon2.Hasher.
func (h *Hasher) WithOptions(opts ...Opt) (err error) {
	for _, opt := range opts {
		if err = opt(h); err != nil {
			return err
		}
	}

	return nil
}

// Copy copies all parameters from this argon2.Hasher to another *argon2.Hasher.
func (h *Hasher) Copy(hasher *Hasher) {
	hasher.variant, hasher.t, hasher.p, hasher.m, hasher.k, hasher.s = h.variant, h.t, h.p, h.m, h.k, h.s
}

// Clone returns a clone from this argon2.Hasher to another *argon2.Hasher.
func (h *Hasher) Clone() *Hasher {
	return &Hasher{
		variant: h.variant,
		t:       h.t,
		p:       h.p,
		m:       h.m,
		k:       h.k,
		s:       h.s,
	}
}

// Merge copies all parameters from this argon2.Hasher to another *argon2.Hasher where the parameters are unset.
func (h *Hasher) Merge(hash *Hasher) {
	if hash.variant == VariantNone {
		hash.variant = h.variant
	}

	if hash.t == 0 {
		hash.t = h.t
	}

	if hash.p == 0 {
		hash.p = h.p
	}

	if hash.m == 0 {
		hash.m = h.m
	}

	if hash.k == 0 {
		hash.k = h.k
	}

	if hash.s == 0 {
		hash.s = h.s
	}
}

// Hash performs the hashing operation and returns either a argon2.Digest or an error.
func (h *Hasher) Hash(password string) (digest algorithm.Digest, err error) {
	h.defaults()

	if digest, err = h.hash(password); err != nil {
		return nil, fmt.Errorf(algorithm.ErrFmtHasherHash, AlgName, err)
	}

	return digest, nil
}

func (h *Hasher) hash(password string) (hashed algorithm.Digest, err error) {
	var salt []byte

	if salt, err = random.Bytes(h.s); err != nil {
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

func (h *Hasher) hashWithSalt(passwordRaw string, salt []byte) (digest algorithm.Digest, err error) {
	if s := len(salt); s > SaltLengthMax || s < SaltLengthMin {
		return nil, fmt.Errorf("%w: salt bytes must have a length of between %d and %d but has a length of %d", algorithm.ErrSaltInvalid, SaltLengthMin, SaltLengthMax, len(salt))
	}

	password := []byte(passwordRaw)

	if len(password) > PasswordInputSizeMax {
		return nil, fmt.Errorf("%w: passwordRaw has a length of '%d' but must be less than or equal to %d", algorithm.ErrParameterInvalid, len(password), PasswordInputSizeMax)
	}

	d := &Digest{
		variant: h.variant,
		t:       uint32(h.t),
		p:       uint32(h.p),
		m:       uint32(h.m),
		salt:    salt,
	}

	d.defaults()

	d.key = d.variant.KeyFunc()(password, d.salt, d.t, d.m, d.p, uint32(h.k))

	return d, nil
}

// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (h *Hasher) MustHash(password string) (hashed algorithm.Digest) {
	var err error

	if hashed, err = h.Hash(password); err != nil {
		panic(err)
	}

	return hashed
}

// Validate checks the settings/parameters for this argon2.Hasher and returns an error.
func (h *Hasher) Validate() (err error) {
	if err = h.validate(); err != nil {
		return fmt.Errorf(algorithm.ErrFmtHasherValidation, AlgName, err)
	}

	return nil
}

func (h *Hasher) validate() (err error) {
	h.defaults()

	mMin := h.p * MemoryMinParallelismMultiplier

	if h.m < mMin || h.m > MemoryMax {
		return fmt.Errorf(algorithm.ErrFmtInvalidIntParameter, algorithm.ErrParameterInvalid, "m", mMin, " (p * 8)", MemoryMax, h.m)
	}

	return nil
}

func (h *Hasher) defaults() {
	if h.d {
		return
	}

	h.d = true

	if h.k < KeyLengthMin {
		h.s = KeyLengthDefault
	}

	if h.s < SaltLengthMin {
		h.s = algorithm.SaltLengthDefault
	}
}
