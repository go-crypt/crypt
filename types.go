package crypt

import (
	"fmt"
	"hash"
)

// Digest represents a hashed password. It's implemented by all hashed password results so that when we pass a
// stored hash into its relevant type we can verify the password against the hash.
type Digest interface {
	fmt.Stringer

	Matcher

	Encode() (hash string)
	Decode(encodedDigest string) (err error)
}

// Hash is an interface which implements password hashing.
type Hash interface {
	// Validate checks the hasher configuration to ensure it's valid. This should be used when the Hash is going to be
	// reused and you should use it in conjunction with MustHash.
	Validate() (err error)

	// Hash performs the hashing operation on a password and resets any relevant parameters such as a manually set salt.
	// It then returns a Digest and error.
	Hash(password string) (hashed Digest, err error)

	// HashWithSalt is an overload of Digest that also accepts a salt.
	HashWithSalt(password, salt string) (hashed Digest, err error)

	// MustHash overloads the Hash method and panics if the error is not nil. It's recommended if you use this method to
	// utilize the Validate method first or handle the panic appropriately.
	MustHash(password string) (hashed Digest)
}

// Matcher is an interface used to match passwords.
type Matcher interface {
	Match(password string) (match bool)
	MatchBytes(passwordBytes []byte) (match bool)
	MatchAdvanced(password string) (match bool, err error)
	MatchBytesAdvanced(passwordBytes []byte) (match bool, err error)
}

// HashFunc is a function which returns a hash.Hash.
type HashFunc func() hash.Hash
