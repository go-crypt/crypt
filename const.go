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
	AlgorithmPrefixPBKDF2SHA224 = "pbkdf2-sha224"
	AlgorithmPrefixPBKDF2SHA256 = "pbkdf2-sha256"
	AlgorithmPrefixPBKDF2SHA384 = "pbkdf2-sha384"
	AlgorithmPrefixPBKDF2SHA512 = "pbkdf2-sha512"

	algorithmNameArgon2    = "argon2"
	algorithmNamePBKDF2    = "pbkdf2"
	algorithmNameSHA2Crypt = "sha2crypt"
	algorithmNameBcrypt    = "bcrypt"
	algorithmNameScrypt    = "scrypt"
)

const (
	digestSHA1   = "sha1"
	digestSHA224 = "sha224"
	digestSHA256 = "sha256"
	digestSHA384 = "sha384"
	digestSHA512 = "sha512"
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
	maxInt                = int(^uint(0) >> 1)
	maxSigned32BitInteger = 1<<31 - 1
)

// Storage Formats.
const (
	StorageFormatPrefixLDAPCrypt  = "{CRYPT}"
	StorageFormatPrefixLDAPArgon2 = "{ARGON2}"

	StorageDelimiter          = "$"
	StorageFormatSHACrypt     = "$%s$rounds=%d$%s$%s"
	StorageFormatArgon2       = "$%s$v=%d$m=%d,t=%d,p=%d$%s$%s"
	StorageFormatScrypt       = "$%s$ln=%d,r=%d,p=%d$%s$%s"
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
	// SaltSizeDefault is the default salt size for most implementations.
	SaltSizeDefault = 16

	// KeySizeDefault is the default key size for most implementations.
	KeySizeDefault = 32
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
	Argon2KeySizeMin                          = 4
	Argon2KeySizeMax                          = maxSigned32BitInteger
	Argon2SaltSizeMin                         = 1
	Argon2SaltSizeMax                         = maxSigned32BitInteger
	Argon2IterationsMin                       = 1
	Argon2IterationsMax                       = maxSigned32BitInteger
	Argon2ParallelismMin                      = 1
	Argon2ParallelismMax                      = 16777215
	Argon2MemoryMinParallelismMultiplier      = 8
	Argon2MemoryRoundingParallelismMultiplier = 4
	Argon2MemoryMax                           = maxSigned32BitInteger
	Argon2PasswordInputSizeMax                = maxSigned32BitInteger
	variantArgon2Default                      = Argon2VariantID
)

// bcrypt constants.
const (
	BcryptCostDefault          = 13
	BcryptCostMin              = 10
	BcryptCostMax              = 31
	BcryptPasswordInputSizeMax = 72
	variantBcryptDefault       = BcryptVariantStandard
)

// pbkdf2 constants.
const (
	PBKDF2KeySizeMax              = maxSigned32BitInteger
	PBKDF2SaltSizeMin             = 8
	PBKDF2SaltSizeMax             = maxSigned32BitInteger
	PBKDF2IterationsMin           = 100000
	PBKDF2IterationsMax           = maxSigned32BitInteger
	PBKDF2SHA1IterationsDefault   = 720000
	PBKDF2SHA256IterationsDefault = 310000
	PBKDF2SHA512IterationsDefault = 120000
	variantPBKDF2Default          = PBKDF2VariantSHA256
)

// scrypt constants.
const (
	ScryptKeySizeMin         = 1
	ScryptKeySizeMax         = (1<<32 - 1) * 32
	ScryptSaltSizeMin        = 8
	ScryptSaltSizeMax        = 1024
	ScryptIterationsMin      = 1
	ScryptIterationsDefault  = 16
	ScryptBlockSizeMin       = 1
	ScryptBlockSizeMax       = maxInt / 256
	ScryptBlockSizeDefault   = 8
	ScryptParallelismMin     = 1
	ScryptParallelismDefault = ScryptParallelismMin
)

// SHA2Crypt constants.
const (
	SHA2CryptIterationsMin     = 1000
	SHA2CryptIterationsMax     = 999999999
	SHA2CryptIterationsDefault = 1000000
	SHA2CryptSaltSizeMin       = 1
	SHA2CryptSaltSizeMax       = 16
)
