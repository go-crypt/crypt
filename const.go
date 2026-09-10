package crypt

import (
	"github.com/go-crypt/crypt/internal/encoding"
	"errors"
)

const (
	// Delimiter for all storage formats.
	Delimiter = encoding.DelimiterStr
)

const (
	// StorageFormatPrefixLDAPCrypt is a prefix used by OpenLDAP for crypt format encoded digests.
	StorageFormatPrefixLDAPCrypt = "{CRYPT}"

	// StorageFormatPrefixLDAPArgon2 is a prefix used by OpenLDAP for argon2 format encoded digests.
	StorageFormatPrefixLDAPArgon2 = "{ARGON2}"
)

var (
	// ErrDigestNil is returned by the crypt.Digest matcher methods when it does not wrap an algorithm.Digest.
	ErrDigestNil = errors.New("crypt.Digest does not wrap an algorithm.Digest")
)
