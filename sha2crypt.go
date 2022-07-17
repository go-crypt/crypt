package crypt

import (
	"fmt"

	xcrypt "github.com/go-crypt/x/crypt"
)

// NewSHA2CryptHash returns a *SHA2CryptHash without any settings configured. This defaults to a SHA512 hash.Hash
// with 1000000 rounds. These settings can be overriden with the methods with the With prefix.
func NewSHA2CryptHash() *SHA2CryptHash {

	return &SHA2CryptHash{}
}

// SHA2CryptHash is a Hash for SHA2Crypt which provides a builder design pattern.
type SHA2CryptHash struct {
	variant SHA2CryptVariant

	bytesSalt uint32

	rounds uint32

	defaults, unsafe bool
}

// NewSHA2CryptSHA256Hash returns a *SHA2CryptHash with the SHA256 hash.Hash which defaults to 1000000 rounds. These
//settings can be overriden with the methods with the With prefix.
func NewSHA2CryptSHA256Hash() *SHA2CryptHash {
	return NewSHA2CryptHash().WithSHA256()
}

// NewSHA2CryptSHA512Hash returns a *SHA2CryptHash with the SHA512 hash.Hash which defaults to 1000000 rounds. These
//settings can be overriden with the methods with the With prefix.
func NewSHA2CryptSHA512Hash() *SHA2CryptHash {
	return NewSHA2CryptHash().WithSHA512()
}

// WithSHA256 adjusts this SHA2CryptHash to utilize the SHA256 hash.Hash.
func (h *SHA2CryptHash) WithSHA256() *SHA2CryptHash {
	h.variant = SHA2CryptVariantSHA256

	return h
}

// WithSHA512 adjusts this SHA2CryptHash to utilize the SHA512 hash.Hash.
func (h *SHA2CryptHash) WithSHA512() *SHA2CryptHash {
	h.variant = SHA2CryptVariantSHA512

	return h
}

// WithoutValidation disables the validation and allows potentially unsafe values. Use at your own risk.
func (h *SHA2CryptHash) WithoutValidation() *SHA2CryptHash {
	h.unsafe = true

	return h
}

// WithRounds sets the rounds parameter of the resulting SHA2CryptDigest. Default is 1000000.
func (h *SHA2CryptHash) WithRounds(rounds uint32) *SHA2CryptHash {
	h.rounds = rounds

	return h
}

// WithSaltLength adjusts the salt size (in bytes) of the resulting SHA2CryptDigest. Minimum 1, Maximum 16. Default is
// 16.
func (h *SHA2CryptHash) WithSaltLength(bytes uint32) *SHA2CryptHash {
	h.bytesSalt = bytes

	return h
}

// Hash performs the hashing operation and returns either a Digest or an error.
func (h *SHA2CryptHash) Hash(password string) (digest Digest, err error) {
	h.setDefaults()

	var salt []byte

	if salt, err = randomBytes(h.bytesSalt); err != nil {
		return nil, fmt.Errorf("sha2crypt hashing error: %w: %v", ErrSaltReadRandomBytes, err)
	}

	return h.hashWithSalt(password, salt)
}

// HashWithSalt overloads the Hash method allowing the user to provide a salt. It's recommended instead to configure the
// salt size and let this be a random value generated using crypto/rand.
func (h *SHA2CryptHash) HashWithSalt(password, salt string) (digest Digest, err error) {
	var saltBytes []byte

	if saltBytes, err = h.validateSalt(salt); err != nil {
		return nil, err
	}

	return h.hashWithSalt(password, saltBytes)
}

func (h *SHA2CryptHash) hashWithSalt(password string, salt []byte) (digest Digest, err error) {
	if err = h.validate(); err != nil {
		return nil, err
	}

	d := &SHA2CryptDigest{
		rounds: int(h.rounds),
		salt:   salt,
	}

	d.key = xcrypt.Key(d.variant.HashFunc(), []byte(password), d.salt, d.rounds)

	return d, nil
}

// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (h *SHA2CryptHash) MustHash(password string) (digest Digest) {
	var err error

	if digest, err = h.Hash(password); err != nil {
		panic(err)
	}

	return digest
}

// Validate checks the settings/parameters for this Hash and returns an error.
func (h *SHA2CryptHash) Validate() (err error) {
	return h.validate()
}

func (h *SHA2CryptHash) validate() (err error) {
	h.setDefaults()

	if h.unsafe {
		return nil
	}

	return nil
}

func (h *SHA2CryptHash) validateSalt(salt string) (saltBytes []byte, err error) {
	saltBytes = []byte(salt)

	if h.unsafe {
		return saltBytes, nil
	}

	if len(saltBytes) < sha2cryptSaltMinBytes || len(saltBytes) > sha2cryptSaltMaxBytes {
		return nil, fmt.Errorf("sha2crypt validation error: %w: salt must be between %d and %d bytes but is %d bytes", ErrSaltInvalid, sha2cryptSaltMinBytes, sha2cryptSaltMaxBytes, len(saltBytes))
	}

	return saltBytes, nil
}

func (h *SHA2CryptHash) setDefaults() {
	if h.defaults {
		return
	}

	h.defaults = true

	switch {
	case h.rounds <= 0:
		h.rounds = sha2cryptRoundsDefault
	case h.rounds < sha2cryptRoundsMin:
		h.rounds = sha2cryptRoundsMin
	case h.rounds > sha2cryptRoundsMax:
		h.rounds = sha2cryptRoundsMax
	}

	switch {
	case h.bytesSalt == 0:
		h.bytesSalt = defaultSaltSize
	case h.bytesSalt > sha2cryptSaltMaxBytes:
		h.bytesSalt = sha2cryptSaltMaxBytes
	}

	switch h.variant {
	case SHA2CryptVariantNone:
		h.variant = SHA2CryptVariantSHA512
	case SHA2CryptVariantSHA256, SHA2CryptVariantSHA512:
		break
	default:
		h.variant = SHA2CryptVariantSHA512
	}
}
