package crypt

const (
	DigestSHA1   = "sha1"
	DigestSHA224 = "sha224"
	DigestSHA256 = "sha256"
	DigestSHA384 = "sha384"
	DigestSHA512 = "sha512"
)

const (
	// SaltSizeDefault is the default salt size for most implementations.
	SaltSizeDefault = 16

	// KeySizeDefault is the default key size for most implementations.
	KeySizeDefault = 32
)
