package crypt

import (
	"fmt"
	"strings"
)

// NewDigest creates a new Digest given a Digest implementation and an encoded digest string.
func NewDigest(encodedDigest string, digest Digest) (d Digest, err error) {
	if err = digest.Decode(encodedDigest); err != nil {
		return nil, err
	}

	return digest, nil
}

// Decode an encoded digest string into a Digest.
func Decode(encodedDigest string) (digest Digest, err error) {
	encodedDigest = NormalizeEncodedDigest(encodedDigest)

	parts := strings.Split(encodedDigest, StorageDelimiter)

	if len(parts) < 3 {
		return nil, fmt.Errorf("decode error: %w", ErrEncodedHashInvalidFormat)
	}

	switch parts[1] {
	case AlgorithmPrefixSHA256, AlgorithmPrefixSHA512:
		return NewDigest(encodedDigest, &SHA2CryptDigest{})
	case AlgorithmPrefixScrypt:
		return NewDigest(encodedDigest, &ScryptDigest{})
	case AlgorithmPrefixBcrypt:
		return NewDigest(encodedDigest, &BcryptDigest{})
	case AlgorithmPrefixArgon2i, AlgorithmPrefixArgon2d, AlgorithmPrefixArgon2id:
		return NewDigest(encodedDigest, &Argon2Digest{})
	case AlgorithmPrefixPBKDF2, AlgorithmPrefixPBKDF2SHA1, AlgorithmPrefixPBKDF2SHA256, AlgorithmPrefixPBKDF2SHA512:
		return NewDigest(encodedDigest, &PBKDF2Digest{})
	default:
		return nil, fmt.Errorf("decode error: %w: identifier '%s' is unknown", ErrEncodedHashInvalidIdentifier, parts[1])
	}
}
