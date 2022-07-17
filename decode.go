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
	var prefix string

	encodedDigest, prefix, err = decodePrefixAndNormalize(encodedDigest)

	return decode(encodedDigest, prefix, false)
}

// DecodeWithPlainText is an extended version of Decode but also explicitly allows decoding plain text storage formats.
func DecodeWithPlainText(encodedDigest string) (digest Digest, err error) {
	var prefix string

	encodedDigest, prefix, err = decodePrefixAndNormalize(encodedDigest)

	return decode(encodedDigest, prefix, true)
}

func decodePrefixAndNormalize(encodedDigest string) (normalizedEncodedDigest, prefix string, err error) {
	encodedDigest = NormalizeEncodedDigest(encodedDigest)

	parts := strings.Split(encodedDigest, StorageDelimiter)

	if len(parts) < 3 {
		return "", "", fmt.Errorf("decode error: %w", ErrEncodedHashInvalidFormat)
	}

	return encodedDigest, parts[1], nil
}

func decode(encodedDigest, prefix string, plaintext bool) (digest Digest, err error) {
	switch prefix {
	case AlgorithmPrefixSHA256, AlgorithmPrefixSHA512:
		return NewDigest(encodedDigest, &SHA2CryptDigest{})
	case AlgorithmPrefixScrypt:
		return NewDigest(encodedDigest, &ScryptDigest{})
	case AlgorithmPrefixBcrypt, AlgorithmPrefixBcryptSHA256:
		return NewDigest(encodedDigest, &BcryptDigest{})
	case AlgorithmPrefixArgon2i, AlgorithmPrefixArgon2d, AlgorithmPrefixArgon2id:
		return NewDigest(encodedDigest, &Argon2Digest{})
	case AlgorithmPrefixPBKDF2, AlgorithmPrefixPBKDF2SHA1, AlgorithmPrefixPBKDF2SHA256, AlgorithmPrefixPBKDF2SHA512:
		return NewDigest(encodedDigest, &PBKDF2Digest{})
	case AlgorithmPrefixPlainText, AlgorithmPrefixBase64:
		if plaintext {
			return NewDigest(encodedDigest, &PlainTextDigest{})
		}

		return nil, fmt.Errorf("decode error: %w: identifier '%s' is plaintext but plaintext has not been explicitly permitted", ErrEncodedHashInvalidIdentifier, prefix)
	default:
		return nil, fmt.Errorf("decode error: %w: identifier '%s' is unknown", ErrEncodedHashInvalidIdentifier, prefix)
	}
}
