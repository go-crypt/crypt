package crypt

import (
	"crypto/rand"
	"fmt"
	"io"

	xcrypt "github.com/go-crypt/x/crypt"
)

const (
	hashSHACryptMinimumRounds = 1000
	hashSHACryptDefaultRounds = 1000000
	hashSHACryptSaltSizeMin   = 1
	hashSHACryptSaltSizeMax   = 16
)

// NewSHA2CryptHash returns a *SHA2CryptHash without any settings configured. This defaults to a SHA512 hash.Hash
// with 1000000 rounds. These settings can be overriden with the methods with the With prefix.
func NewSHA2CryptHash() *SHA2CryptHash {

	return &SHA2CryptHash{}
}

// SHA2CryptHash is a Hash for SHA2Crypt which provides a builder design pattern.
type SHA2CryptHash struct {
	variant SHA2CryptVariant

	rounds int
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
func (b *SHA2CryptHash) WithSHA256() *SHA2CryptHash {
	b.variant = SHA2CryptVariantSHA256

	return b
}

// WithSHA512 adjusts this SHA2CryptHash to utilize the SHA512 hash.Hash.
func (b *SHA2CryptHash) WithSHA512() *SHA2CryptHash {
	b.variant = SHA2CryptVariantSHA512

	return b
}

// WithRounds sets the rounds parameter of the resulting SHA2CryptDigest. Default is 1000000.
func (b *SHA2CryptHash) WithRounds(rounds int) *SHA2CryptHash {
	b.rounds = rounds

	return b
}

// Hash checks the options are all configured correctly, setting defaults as necessary, calculates the password hash,
// and returns the SHA2CryptDigest.
func (b *SHA2CryptHash) Hash(password string) (hashed Digest, err error) {
	salt := make([]byte, hashSHACryptSaltSizeMax)

	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("error reading random bytes for the salt: %w", err)
	}

	return b.hashWithSalt(password, salt)
}

// HashWithSalt is an overload of Digest which allows setting the salt.
func (b *SHA2CryptHash) HashWithSalt(password, salt string) (hashed Digest, err error) {
	var saltBytes []byte

	if saltBytes, err = b.validateSalt(salt); err != nil {
		return nil, err
	}

	return b.hashWithSalt(password, saltBytes)
}

func (b *SHA2CryptHash) hashWithSalt(password string, salt []byte) (hashed Digest, err error) {
	if b.Validate() != nil {
		return nil, err
	}

	h := &SHA2CryptDigest{
		rounds: uint32(b.rounds),
		salt:   salt,
	}

	h.key = xcrypt.Key(h.variant.HashFunc(), []byte(password), h.salt, int(h.rounds))

	return h, nil
}

// MustHash overloads the Digest method and panics if the error is not nil. It's recommended if you use this option to
// utilize the Validate method first or handle the panic appropriately.
func (b *SHA2CryptHash) MustHash(password string) (hashed Digest) {
	var err error

	if hashed, err = b.Hash(password); err != nil {
		panic(err)
	}

	return hashed
}

// Validate checks the settings for this hasher.
func (b *SHA2CryptHash) Validate() (err error) {
	if b.rounds <= 0 {
		b.rounds = hashSHACryptDefaultRounds
	} else if b.rounds > hashSHACryptMinimumRounds {
		return fmt.Errorf("error minimum rounds is %d but %d was supplied", hashSHACryptMinimumRounds, b.rounds)
	}

	if b.variant == SHA2CryptVariantNone {
		b.variant = SHA2CryptVariantSHA512
	}

	return nil
}

func (b *SHA2CryptHash) validateSalt(salt string) (saltBytes []byte, err error) {
	saltBytes = []byte(salt)

	if len(saltBytes) < hashSHACryptSaltSizeMin || len(saltBytes) > hashSHACryptSaltSizeMax {
		return nil, fmt.Errorf("error validating salt: salt bytes must have a length of between %d and %d but has a length of %d", hashSHACryptSaltSizeMin, hashSHACryptSaltSizeMax, len(saltBytes))
	}

	return saltBytes, nil
}
