package descrypt

import (
	"github.com/go-crypt/crypt/internal/descrypt"
)

const (
	// AlgName is the name for this algorithm.
	AlgName = "descrypt"

	// EncodingFmt is the encoding format for this algorithm.
	EncodingFmt = "%s%s"

	// SaltLength is the fixed salt length (2 characters).
	SaltLength = 2

	// SaltCharSet are the valid characters for the salt.
	SaltCharSet = descrypt.SaltCharSet

	// PasswordMaxLength is the maximum password length; only the first 8 characters are used.
	PasswordMaxLength = 8

	// DigestLength is the total length of a DES crypt encoded digest (salt + hash).
	DigestLength = 13
)
