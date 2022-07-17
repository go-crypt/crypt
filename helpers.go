package crypt

import (
	"fmt"
	"strings"
)

// CheckPassword takes the string password and an encoded digest. It decodes the Digest, then performs the
// MatchAdvanced() function on the Digest. If any process returns an error it returns false with the error, otherwise
// it returns the result of MatchAdvanced(). This is just a helper function and implementers can manually invoke this
// process themselves in situations where they may want to store the Digest to perform matches at a later date to avoid
// decoding multiple times for example.
func CheckPassword(password, encodedDigest string) (valid bool, err error) {
	var digest Digest

	if digest, err = Decode(encodedDigest); err != nil {
		return false, err
	}

	return digest.MatchAdvanced(password)
}

// CheckPasswordWithPlainText is the same as CheckPassword however it uses DecodeWithPlainText instead.
func CheckPasswordWithPlainText(password, encodedDigest string) (valid bool, err error) {
	var digest Digest

	if digest, err = DecodeWithPlainText(encodedDigest); err != nil {
		return false, err
	}

	return digest.MatchAdvanced(password)
}

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

	if encodedDigest, prefix, err = decodePrefixAndNormalize(encodedDigest); err != nil {
		return nil, err
	}

	return decode(encodedDigest, prefix, false)
}

// DecodeWithPlainText is an extended version of Decode but also explicitly allows decoding plain text storage formats.
func DecodeWithPlainText(encodedDigest string) (digest Digest, err error) {
	var prefix string

	if encodedDigest, prefix, err = decodePrefixAndNormalize(encodedDigest); err != nil {
		return nil, err
	}

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
