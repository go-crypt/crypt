package crypt

import (
	"fmt"
)

// NewArgon2Hash returns a *Argon2Hash without any settings configured. This defaults to the id variant with the
// low memory RFC9106 low memory profile.
func NewArgon2Hash() *Argon2Hash {
	return &Argon2Hash{}
}

// NewArgon2IDHash returns a *Argon2Hash with just the ID variant configured. This defaults to the low memory RFC9106
// low memory profile.
func NewArgon2IDHash() *Argon2Hash {
	return NewArgon2Hash().WithVariant(Argon2VariantID)
}

// NewArgon2IHash returns a *Argon2Hash with just the I variant configured. This defaults to the low memory RFC9106
// low memory profile.
func NewArgon2IHash() *Argon2Hash {
	return NewArgon2Hash().WithVariant(Argon2VariantI)
}

// NewArgon2DHash returns a *Argon2Hash with just the D variant configured. This defaults to the low memory RFC9106
// low memory profile.
func NewArgon2DHash() *Argon2Hash {
	return NewArgon2Hash().WithVariant(Argon2VariantD)
}

// Argon2Hash is a Hash for Argon2 which provides a builder design pattern.
type Argon2Hash struct {
	variant Argon2Variant

	s, k, m, t, p uint32

	unsafe bool
}

// WithVariant adjusts the variant of the Argon2Digest algorithm. Valid values are I, D, ID. Default is
// argon2id.
func (h *Argon2Hash) WithVariant(variant Argon2Variant) *Argon2Hash {
	switch variant {
	case Argon2VariantI, Argon2VariantD, Argon2VariantID:
		h.variant = variant
	}

	return h
}

// WithProfile sets a specific Argon2Profile.
func (h *Argon2Hash) WithProfile(profile Argon2Profile) *Argon2Hash {
	profile.Params().CopyParamsTo(h)

	return h
}

// WithM sets the m parameter in bytes of the resulting Argon2Digest hash. Default is 32768.
func (h *Argon2Hash) WithM(bytes uint32) *Argon2Hash {
	h.m = bytes

	return h
}

// WithP sets the p parameter of the resulting Argon2Digest hash. Default is 4.
func (h *Argon2Hash) WithP(parallelism uint32) *Argon2Hash {
	h.p = parallelism

	return h
}

// WithT sets the t parameter of the resulting Argon2Digest hash. Default is 4.
func (h *Argon2Hash) WithT(time uint32) *Argon2Hash {
	h.t = time

	return h
}

// WithK adjusts the key length of the resulting Argon2Digest hash. Default is 32.
func (h *Argon2Hash) WithK(length uint32) *Argon2Hash {
	h.k = length

	return h
}

// WithS adjusts the salt length of the resulting Argon2Digest hash. Default is 16.
func (h *Argon2Hash) WithS(length uint32) *Argon2Hash {
	h.s = length

	return h
}

// CopyParamsTo copies all parameters from this Argon2Hash to another *Argon2Hash.
func (h Argon2Hash) CopyParamsTo(hash *Argon2Hash) {
	hash.t, hash.p, hash.m, hash.k, hash.s = h.t, h.p, h.m, h.k, h.s
}

// CopyUnsetParamsTo copies all parameters from this Argon2Hash to another *Argon2Hash where the parameters are unset.
func (h Argon2Hash) CopyUnsetParamsTo(hash *Argon2Hash) {
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

// Hash performs the hashing operation and returns either a Digest or an error.
func (h *Argon2Hash) Hash(password string) (hashed Digest, err error) {
	h.setDefaults()

	var salt []byte

	if salt, err = randomBytes(h.s); err != nil {
		return nil, fmt.Errorf("argon2 hashing error: %w: %v", ErrSaltReadRandomBytes, err)
	}

	return h.hashWithSalt(password, salt)
}

// HashWithSalt overloads the Hash method allowing the user to provide a salt. It's recommended instead to configure the
// salt size and let this be a random value generated using crypto/rand.
func (h *Argon2Hash) HashWithSalt(password, salt string) (hashed Digest, err error) {
	h.setDefaults()

	var saltBytes []byte

	if saltBytes, err = h.validateSalt(salt); err != nil {
		return nil, err
	}

	return h.hashWithSalt(password, saltBytes)
}

func (h *Argon2Hash) hashWithSalt(password string, salt []byte) (digest Digest, err error) {
	if err = h.validate(); err != nil {
		return nil, err
	}

	passwordBytes := []byte(password)

	if len(passwordBytes) > maxUnsigned32BitInteger {
		return nil, fmt.Errorf("argon2 hashing error: %w: password has a length of '%d' but must be less than or equal to %d", ErrParameterInvalid, len(passwordBytes), maxUnsigned32BitInteger)
	}

	d := &Argon2Digest{
		variant: h.variant,
		t:       h.t,
		p:       h.p,
		m:       h.m,
		k:       h.k,
		salt:    salt,
	}

	d.key = d.variant.KeyFunc()(passwordBytes, d.salt, d.t, d.m, d.p, d.k)

	return d, nil
}

// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (h *Argon2Hash) MustHash(password string) (hashed Digest) {
	var err error

	if hashed, err = h.Hash(password); err != nil {
		panic(err)
	}

	return hashed
}

// Validate checks the settings/parameters for this Hash and returns an error.
func (h *Argon2Hash) Validate() (err error) {
	return h.validate()
}

func (h *Argon2Hash) validate() (err error) {
	h.setDefaults()

	if h.unsafe {
		return nil
	}

	if h.p > argon2ParallelismMax {
		return fmt.Errorf("argon2 hashing error: %w: parameter 'p' must be between 1 and %d but is set to '%d'", ErrParameterInvalid, argon2ParallelismMax, h.p)
	}

	mMin := h.p * argon2MemoryMinParallelismMultiplier

	if h.m < mMin {
		return fmt.Errorf("argon2 hashing error: %w: parameter 'm' must be between %d (p * 8) and %d but is set to '%d'", ErrParameterInvalid, mMin, argon2ParallelismMax, h.p)
	}

	return nil
}

func (h *Argon2Hash) validateSalt(salt string) (saltBytes []byte, err error) {
	saltBytes = []byte(salt)

	if len(saltBytes) < argon2SaltMinBytes || len(saltBytes) > maxUnsigned32BitInteger {
		return nil, fmt.Errorf("argon2 hashing error: %w: salt bytes must have a length of between %d and %d but has a length of %d", ErrSaltInvalid, argon2SaltMinBytes, maxUnsigned32BitInteger, len(saltBytes))
	}

	return saltBytes, nil
}

func (h *Argon2Hash) setDefaults() {
	if h.variant == Argon2VariantNone {
		h.variant = argon2VariantDefault
	}

	Argon2ProfileRFC9106LowMemory.Params().CopyUnsetParamsTo(h)

	/*
	   Memory size m MUST be an integer number of kibibytes from 8*p to
	   2^(32)-1.  The actual number of blocks is m', which is m rounded
	   down to the nearest multiple of 4*p.
	*/

	pM := h.p * argon2MemoryRounderParallelismMultiplier

	h.m = roundDownToNearestMultiple(h.m, pM)
}
