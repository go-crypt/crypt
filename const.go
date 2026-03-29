package crypt

import (
	"github.com/go-crypt/crypt/internal/encoding"
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

const (
	// StorageFormatPrefixCiscoType8 is the prefix for Cisco IOS Type 8 (PBKDF2-SHA256) password hashes.
	StorageFormatPrefixCiscoType8 = "$8$"

	// StorageFormatPrefixCiscoType9 is the prefix for Cisco IOS Type 9 (scrypt) password hashes.
	StorageFormatPrefixCiscoType9 = "$9$"

	// StorageFormatPrefixCiscoType10 is the prefix for Cisco ASA Type 10 (PBKDF2-SHA512) password hashes.
	StorageFormatPrefixCiscoType10 = "$sha512$"

	// CiscoType8Iterations is the fixed iteration count for Cisco Type 8 (PBKDF2-SHA256).
	CiscoType8Iterations = 20000

	// CiscoType9LN is the log2(N) parameter for Cisco Type 9 (scrypt). N=16384.
	CiscoType9LN = 14

	// CiscoType9R is the block size parameter for Cisco Type 9 (scrypt).
	CiscoType9R = 1

	// CiscoType9P is the parallelism parameter for Cisco Type 9 (scrypt).
	CiscoType9P = 1
)
