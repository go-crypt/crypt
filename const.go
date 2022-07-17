package crypt

import (
	"encoding/base64"
	"regexp"
)

// Algorithm Prefixes.
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
	AlgorithmPrefixScrypt       = "scrypt"
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
)

var (
	reAlgorithmPrefixPBKDF2 = regexp.MustCompile(`^\{(PBKDF2(-SHA\d+)?)}(\d+\$.*)$`)
)

const (
	maxUnsigned32BitInteger = 4294967295
)

// Storage Formats.
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
	defaultSaltSize = 16
	defaultKeySize  = 32
)

const (
	encodeTypeA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"
)

var (
	b64rs = base64.RawStdEncoding
	b64ra = base64.NewEncoding(encodeTypeA).WithPadding(base64.NoPadding)
)

// argon2 constants.
const (
	argon2SaltMinBytes                       = 1
	argon2ParallelismMax                     = 16777215
	argon2MemoryMinParallelismMultiplier     = 8
	argon2MemoryRounderParallelismMultiplier = 4
)

// bcrypt constants.
const (
	bcryptCostDefault       = 13
	bcryptCostMin           = 10
	bcryptPasswordMaxLength = 72
	bcryptVariantDefault    = BcryptVariantStandard
)

// pbkdf2 constants.
const (
	pbkdf2IterationsDefaultSHA1   = 720000
	pbkdf2IterationsDefaultSHA256 = 310000
	pbkdf2IterationsDefaultSHA512 = 120000
	pbkdf2IterationsMin           = 100000
	pbkdf2VariantDefault          = PBKDF2VariantSHA256
	pbkdf2SaltMinBytes            = 8
)

// scrypt constants.
const (
	scryptRoundsDefault      = 16
	scryptBlockSizeDefault   = 8
	scryptParallelismDefault = 1
)

const (
	sha2cryptRoundsMin     = 1000
	sha2cryptRoundsMax     = 999999999
	sha2cryptRoundsDefault = 1000000
	sha2cryptSaltMinBytes  = 1
	sha2cryptSaltMaxBytes  = 16
)
