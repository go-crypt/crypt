package crypt

import (
	"github.com/go-crypt/crypt/internal/encoding"
)

const (
	// Delimiter for all storage formats.
	Delimiter = encoding.DelimiterStr
)

const (
	// StorageFormatPrefixLDAPCrypt is a prefix used by LDAP for crypt format encoded digests.
	StorageFormatPrefixLDAPCrypt = "{CRYPT}"

	// StorageFormatPrefixLDAPArgon2 is a prefix used by LDAP for argon2 format encoded digests.
	StorageFormatPrefixLDAPArgon2 = "{ARGON2}"

	// StorageFormatPrefixLDAPClearText is a prefix used by LDAP for cleartext passwords.
	StorageFormatPrefixLDAPClearText = "{CLEARTEXT}"
)
