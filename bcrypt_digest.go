package crypt

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/x/bcrypt"
)

// BcryptDigest is a digest which handles bcrypt hashes.
type BcryptDigest struct {
	cost int

	salt, key []byte
}

// Match returns true if the string password matches the current Digest.
func (d BcryptDigest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current Digest.
func (d BcryptDigest) MatchBytes(passwordBytes []byte) (match bool) {
	match, _ = d.MatchBytesAdvanced(passwordBytes)

	return match
}

// MatchAdvanced is the same as Match except if there is an error it returns that as well.
func (d BcryptDigest) MatchAdvanced(password string) (match bool, err error) {
	return d.MatchBytesAdvanced([]byte(password))
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d BcryptDigest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	var key []byte

	if key, err = bcrypt.Key(passwordBytes, d.salt, d.cost); err != nil {
		return false, fmt.Errorf("bcrypt match error: %w", err)
	}

	return subtle.ConstantTimeCompare(d.key, key) == 1, nil
}

// Encode returns the encoded form of this digest.
func (d *BcryptDigest) Encode() string {
	return fmt.Sprintf(StorageFormatBcrypt, AlgorithmPrefixBcrypt, d.cost, bcrypt.Base64Encode(d.salt), d.key)
}

// Decode takes an encodedDigest string and parses it into this Digest.
func (d *BcryptDigest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := splitDigest(encodedDigest, StorageDelimiter)

	if len(encodedDigestParts) != 4 {
		return fmt.Errorf("bcrypt decode error: %w", ErrEncodedHashInvalidFormat)
	}

	identifier, cost, secret := encodedDigestParts[1], encodedDigestParts[2], encodedDigestParts[3]

	switch strings.ToLower(identifier) {
	case AlgorithmPrefixBcrypt, algorithmPrefixBcryptA, algorithmPrefixBcryptX, algorithmPrefixBcryptY:
		break
	default:
		return fmt.Errorf("bcrypt decode error: %w: the '%s' identifier is not valid for a bcrypt encoded hash", ErrEncodedHashInvalidIdentifier, identifier)
	}

	if d.cost, err = strconv.Atoi(cost); err != nil {
		return fmt.Errorf("bcrypt decode error: %w: cost could not be parsed: %v", ErrEncodedHashInvalidOptionValue, err)
	}

	salt, key := bcrypt.DecodeSecret([]byte(secret))

	if d.salt, err = bcrypt.Base64Decode(salt); err != nil {
		return fmt.Errorf("bcrypt decode error: %w: %v", ErrEncodedHashSaltEncoding, err)
	}

	d.key = key

	return nil
}

// String returns the storable format of the Digest encoded hash.
func (d BcryptDigest) String() string {
	return d.Encode()
}

func (d BcryptDigest) secret() []byte {
	buf := bytes.Buffer{}

	buf.Write(d.salt)
	buf.Write(d.key)

	return buf.Bytes()
}
