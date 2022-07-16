package crypt

import (
	"encoding/base64"
	"regexp"
)

const (
	AlgorithmPrefixPlainText    = "plaintext"
	AlgorithmPrefixBase64       = "base64"
	AlgorithmPrefixArgon2i      = "argon2i"
	AlgorithmPrefixArgon2d      = "argon2d"
	AlgorithmPrefixArgon2id     = "argon2id"
	AlgorithmPrefixBcrypt       = "2b"
	AlgorithmPrefixBcryptSHA256 = "bcrypt-sha256"
	AlgorithmPrefixSHA256       = "5"
	AlgorithmPrefixSHA512       = "6"
	AlgorithmPrefixScrypt       = "7"
	AlgorithmPrefixPBKDF2       = "pbkdf2"
	AlgorithmPrefixPBKDF2SHA1   = "pbkdf2-sha1"
	AlgorithmPrefixPBKDF2SHA256 = "pbkdf2-sha256"
	AlgorithmPrefixPBKDF2SHA224 = "pbkdf2-sha224"
	AlgorithmPrefixPBKDF2SHA384 = "pbkdf2-sha384"
	AlgorithmPrefixPBKDF2SHA512 = "pbkdf2-sha512"
)

const (
	algorithmPrefixBcryptNormalized = StorageDelimiter + AlgorithmPrefixBcrypt + StorageDelimiter
	algorithmPrefixBcrypt           = StorageDelimiter + "2" + StorageDelimiter
	algorithmPrefixBcryptA          = StorageDelimiter + "2a" + StorageDelimiter
	algorithmPrefixBcryptX          = StorageDelimiter + "2x" + StorageDelimiter
	algorithmPrefixBcryptY          = StorageDelimiter + "2y" + StorageDelimiter
	algorithmPrefixScryptNormalized = StorageDelimiter + AlgorithmPrefixScrypt + StorageDelimiter
	algorithmPrefixScryptScrypt     = StorageDelimiter + "scrypt" + StorageDelimiter
)

var (
	reAlgorithmPrefixPBKDF2 = regexp.MustCompile(`^\{(PBKDF2(-SHA\d+)?)}(\d+\$.*)$`)
)

const (
	maxUnsigned32BitInteger = 4294967295
)

const (
	StorageFormatPrefixLDAPCrypt  = "{CRYPT}"
	StorageFormatPrefixLDAPArgon2 = "{ARGON2}"

	StorageDelimiter          = "$"
	StorageFormatSHACrypt     = "$%s$rounds=%d$%s$%s"
	StorageFormatArgon2       = "$%s$v=%d$m=%d,t=%d,p=%d,k=%d$%s$%s"
	StorageFormatScrypt       = "$%s$ln=%d,r=%d,p=%d,k=%d$%s$%s"
	StorageFormatBcrypt       = "$%s$%d$%s%s"
	StorageFormatBcryptSHA256 = "$%s$v=2,t=%s,r=%d$%s$%s"
	StorageFormatPBKDF2       = "$%s$%d$%s$%s"
	StorageFormatSimple       = "$%s$%s"
)

const (
	oV  = "v"
	oK  = "k"
	oM  = "m"
	oT  = "t"
	oP  = "p"
	oR  = "r"
	oLN = "ln"
)

const (
	DigestSHA1   = "sha1"
	DigestSHA256 = "sha256"
	DigestSHA224 = "sha224"
	DigestSHA384 = "sha384"
	DigestSHA512 = "sha512"
)

const (
	defaultSaltSize = 16
	defaultKeySize  = 32
)

const (
	encodeTypeA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"
	encodeTypeB = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

var (
	b64rs = base64.RawStdEncoding
	b64ru = base64.RawURLEncoding
	b64ra = base64.NewEncoding(encodeTypeA).WithPadding(base64.NoPadding)
	b64sa = base64.NewEncoding(encodeTypeA).WithPadding(base64.StdPadding)
)
