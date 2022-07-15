package crypt

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/x/scrypt"
)

type ScryptDigest struct {
	ln, r, p, k int

	salt, key []byte
}

func (d ScryptDigest) n() (n int) {
	for i := 1; i < d.ln; i++ {
		if i == 1 {
			n = 2 * 2
		} else {
			n = n * 2
		}
	}

	return n
}

func (d ScryptDigest) Match(password string) (match bool) {
	if len(d.key) == 0 {
		return false
	}

	key, err := scrypt.Key([]byte(password), d.salt, d.n(), d.r, d.p, d.k)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(d.key, key) == 1
}

func (d *ScryptDigest) Encode() string {
	return fmt.Sprintf(StorageFormatScrypt,
		AlgorithmPrefixScrypt,
		d.ln, d.r, d.p, d.k,
		b64rs.EncodeToString(d.salt), b64rs.EncodeToString(d.key),
	)
}

func (d *ScryptDigest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := strings.Split(encodedDigest, StorageDelimiter)

	if len(encodedDigestParts) != 5 {
		return fmt.Errorf("scrypt: encoded digest does not have the correct number of parts: should be 4 but has %d", len(encodedDigestParts)-1)
	}

	prefix, options, salt, key := encodedDigestParts[1], encodedDigestParts[2], encodedDigestParts[3], encodedDigestParts[4]

	if prefix != AlgorithmPrefixScrypt {
		return fmt.Errorf("scrypt: algorithm identifier '%s' is not valid for scrypt decoding", prefix)
	}

	d.ln, d.r, d.p, d.k = hashScryptDefaultRounds, hashScryptDefaultBlockSize, hashScryptDefaultParallelism, defaultKeySize

	for _, opt := range strings.Split(options, ",") {
		pair := strings.SplitN(opt, "=", 2)

		if len(pair) != 2 {
			return fmt.Errorf("scrypt: hash invalid option '%s'", opt)
		}

		k, v := pair[0], pair[1]

		switch k {
		case "ln":
			d.ln, err = strconv.Atoi(v)
		case "r":
			d.r, err = strconv.Atoi(v)
		case "p":
			d.p, err = strconv.Atoi(v)
		case "k":
			d.k, err = strconv.Atoi(v)
		default:
			err = fmt.Errorf("scrypt: option '%s' with value '%s' is unknown", k, v)
		}

		if err != nil {
			return err
		}
	}

	if d.salt, err = b64rs.DecodeString(salt); err != nil {
		return fmt.Errorf("scrypt: salt '%s' could not be decoded: %w", salt, err)
	}

	if d.key, err = b64rs.DecodeString(key); err != nil {
		return fmt.Errorf("scrypt: key '%s' could not be decoded: %w", key, err)
	}

	return nil
}

// String returns the storable format of the Scrypt hash utilizing fmt.Sprintf and StorageFormatArgon2.
func (d ScryptDigest) String() string {
	return d.Encode()
}
