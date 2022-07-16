package crypt

import (
	"errors"
)

var (
	// ErrEncodedHashInvalidFormat is an error returned when an encoded hash has an invalid format.
	ErrEncodedHashInvalidFormat = errors.New("provided encoded hash has an invalid format")

	// ErrEncodedHashInvalidIdentifier is an error returned when an encoded hash has an invalid identifier for the
	// given digest.
	ErrEncodedHashInvalidIdentifier = errors.New("provided encoded hash has an invalid identifier")

	// ErrEncodedHashInvalidVersion is an error returned when an encoded hash has an unsupported or otherwise invalid
	// version.
	ErrEncodedHashInvalidVersion = errors.New("provided encoded hash has an invalid version")

	// ErrEncodedHashInvalidOption is an error returned when an encoded hash has an unsupported or otherwise invalid
	// option in the option field.
	ErrEncodedHashInvalidOption = errors.New("provided encoded hash has an invalid option")

	// ErrEncodedHashInvalidOptionKey is an error returned when an encoded hash has an unknown or otherwise invalid
	// option key in the option field.
	ErrEncodedHashInvalidOptionKey = errors.New("provided encoded hash has an invalid option key")

	// ErrEncodedHashInvalidOptionValue is an error returned when an encoded hash has an unknown or otherwise invalid
	// option value in the option field.
	ErrEncodedHashInvalidOptionValue = errors.New("provided encoded hash has an invalid option value")

	// ErrEncodedHashKeyEncoding is an error returned when an encoded hash has a salt with an invalid or unsupported
	// encoding.
	ErrEncodedHashKeyEncoding = errors.New("provided encoded hash has a key value that can't be decoded")

	// ErrEncodedHashSaltEncoding is an error returned when an encoded hash has a salt with an invalid or unsupported
	// encoding.
	ErrEncodedHashSaltEncoding = errors.New("provided encoded hash has a salt value that can't be decoded")

	// ErrKeyDerivation is returned when a Key function returns an error.
	ErrKeyDerivation = errors.New("failed to derive the key with the provided parameters")

	// ErrSaltEncoding is an error returned when a salt has an invalid or unsupported encoding.
	ErrSaltEncoding = errors.New("provided salt has a value that can't be decoded")

	// ErrReadRandomBytesForSalt is an error returned when generating the random bytes for salt resulted in an error.
	ErrReadRandomBytesForSalt = errors.New("could not read random data for the salt")
)
