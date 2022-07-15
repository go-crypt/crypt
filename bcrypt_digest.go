package crypt

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"strconv"

	"github.com/go-crypt/x/bcrypt"
)

type BcryptDigest struct {
	cost int

	salt, key []byte
}

func (d BcryptDigest) secret() []byte {
	buf := bytes.Buffer{}

	buf.Write(d.salt)
	buf.Write(d.key)

	return buf.Bytes()
}

func (d BcryptDigest) Match(password string) (match bool) {
	key, err := bcrypt.Key([]byte(password), d.salt, d.cost)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(d.key, key) == 1
}

func (d *BcryptDigest) Encode() string {
	return fmt.Sprintf(StorageFormatBcrypt, AlgorithmPrefixBcrypt, d.cost, bcrypt.Base64Encode(d.salt), d.key)
}

func (d *BcryptDigest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := splitDigest(encodedDigest, StorageDelimiter)

	if len(encodedDigestParts) != 4 {
		return fmt.Errorf("bcrypt: hash with incorrect format provided")
	}

	cost, secret := encodedDigestParts[2], encodedDigestParts[3]

	if d.cost, err = strconv.Atoi(cost); err != nil {
		return fmt.Errorf("bcrypt: hash with invalid cost provided: %w", err)
	}

	salt, key := bcrypt.DecodeSecret([]byte(secret))

	if d.salt, err = bcrypt.Base64Decode(salt); err != nil {
		return fmt.Errorf("bcrypt: encoded digest has a salt which can't be decoded: %w", err)
	}

	d.key = key

	return nil
}

// String returns the storable format of the BcryptDigest hash utilizing fmt.Sprintf and StorageFormatArgon2.
func (d BcryptDigest) String() string {
	return d.Encode()
}
