package crypt

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/x/pbkdf2"
)

type PBKDF2Digest struct {
	variant PBKDF2Variant

	iterations int
	k          int
	salt, key  []byte
}

func (d PBKDF2Digest) Match(password string) (match bool) {
	if len(d.key) == 0 {
		return false
	}

	return subtle.ConstantTimeCompare(d.key, pbkdf2.Key([]byte(password), d.salt, d.iterations, d.k, d.variant.HashFunc())) == 1
}

func (d *PBKDF2Digest) Encode() string {
	return fmt.Sprintf(StorageFormatPBKDF2,
		d.variant.String(),
		d.iterations,
		b64rs.EncodeToString(d.salt), b64rs.EncodeToString(d.key),
	)
}

func (d *PBKDF2Digest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := strings.Split(encodedDigest, StorageDelimiter)

	// $pbkdf2-sha256$29000$C.H8PwfgvNdaa21t7Z3zHg$JJEF8JnmHSl.CO49AczNNIPvzNo.KaQGU3T9S3Ebr4M

	if len(encodedDigestParts) != 5 {
		return fmt.Errorf("encoded digest does not have the correct number of parts: should be 4 but has %d", len(encodedDigestParts)-1)
	}

	identifier, rawIterations, rawSalt, rawKey := encodedDigestParts[1], encodedDigestParts[2], encodedDigestParts[3], encodedDigestParts[4]

	d.variant = NewPBKDF2Variant(identifier)

	if d.variant == PBKDF2VariantNone {
		return fmt.Errorf("encoded digest has unknown identifier '%s'", identifier)
	}

	if d.iterations, err = strconv.Atoi(rawIterations); err != nil {
		return fmt.Errorf("encoded digest has an invalid iterations value: %w", err)
	}

	if d.salt, err = b64rs.DecodeString(strings.ReplaceAll(rawSalt, ".", "+")); err != nil {
		return fmt.Errorf("encoded digest has a salt which can't be decoded: %w", err)
	}

	if d.key, err = b64rs.DecodeString(strings.ReplaceAll(rawKey, ".", "+")); err != nil {
		return fmt.Errorf("encoded digest has a key which can't be decoded: %w", err)
	}

	d.k = len(d.key)

	return nil
}

// String returns the storable format of the PBKDF2Digest hash utilizing fmt.Sprintf and StorageFormatArgon2.
func (d PBKDF2Digest) String() string {
	return d.Encode()
}
