package crypt

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/x/scrypt"
)

// ScryptDigest is a Digest which handles scrypt hashes.
type ScryptDigest struct {
	ln, r, p int

	salt, key []byte
}

// Match returns true if the string password matches the current Digest.
func (d *ScryptDigest) Match(password string) (match bool) {
	return d.MatchBytes([]byte(password))
}

// MatchBytes returns true if the []byte passwordBytes matches the current Digest.
func (d *ScryptDigest) MatchBytes(passwordBytes []byte) (match bool) {
	match, _ = d.MatchBytesAdvanced(passwordBytes)

	return match
}

// MatchAdvanced is the same as Match except if there is an error it returns that as well.
func (d *ScryptDigest) MatchAdvanced(password string) (match bool, err error) {
	return d.MatchBytesAdvanced([]byte(password))
}

// MatchBytesAdvanced is the same as MatchBytes except if there is an error it returns that as well.
func (d *ScryptDigest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	if len(d.key) == 0 {
		return false, fmt.Errorf("scrypt match error: %w: key has 0 bytes", ErrPasswordInvalid)
	}

	var key []byte

	if key, err = scrypt.Key(passwordBytes, d.salt, d.n(), d.r, d.p, len(d.key)); err != nil {
		return false, fmt.Errorf("scrypt match error: %w", err)
	}

	return subtle.ConstantTimeCompare(d.key, key) == 1, nil
}

// Encode returns the encoded form of this Digest.
func (d *ScryptDigest) Encode() string {
	return fmt.Sprintf(StorageFormatScrypt,
		AlgorithmPrefixScrypt,
		d.ln, d.r, d.p,
		b64rs.EncodeToString(d.salt), b64rs.EncodeToString(d.key),
	)
}

// Decode takes an encodedDigest string and parses it into this Digest.
func (d *ScryptDigest) Decode(encodedDigest string) (err error) {
	encodedDigestParts := strings.Split(encodedDigest, StorageDelimiter)

	if len(encodedDigestParts) != 5 {
		return fmt.Errorf("scrypt decode error: %w", ErrEncodedHashInvalidFormat)
	}

	identifier, options, salt, key := encodedDigestParts[1], encodedDigestParts[2], encodedDigestParts[3], encodedDigestParts[4]

	if identifier != AlgorithmPrefixScrypt {
		return fmt.Errorf("scrypt decode error: %w: the '%s' identifier is not valid for an scrypt encoded hash", ErrEncodedHashInvalidIdentifier, identifier)
	}

	d.ln, d.r, d.p = scryptRoundsDefault, scryptBlockSizeDefault, scryptParallelismDefault

	for _, opt := range strings.Split(options, ",") {
		pair := strings.SplitN(opt, "=", 2)

		if len(pair) != 2 {
			return fmt.Errorf("scrypt decode error: %w: option '%s' is invalid", ErrEncodedHashInvalidOption, opt)
		}

		k, v := pair[0], pair[1]

		switch k {
		case oLN:
			d.ln, err = strconv.Atoi(v)
		case oR:
			d.r, err = strconv.Atoi(v)
		case oP:
			d.p, err = strconv.Atoi(v)
		default:
			return fmt.Errorf("scrypt decode error: %w: option '%s' with value '%s' is unknown", ErrEncodedHashInvalidOptionKey, k, v)
		}

		if err != nil {
			return fmt.Errorf("scrypt decode error: %w: option '%s' has invalid value '%s': %v", ErrEncodedHashInvalidOptionValue, k, v, err)
		}
	}

	if d.salt, err = b64rs.DecodeString(salt); err != nil {
		return fmt.Errorf("scrypt decode error: %w: %+v", ErrEncodedHashSaltEncoding, err)
	}

	if d.key, err = b64rs.DecodeString(key); err != nil {
		return fmt.Errorf("scrypt decode error: %w: %v", ErrEncodedHashKeyEncoding, err)
	}

	return nil
}

// String returns the storable format of the Digest encoded hash.
func (d *ScryptDigest) String() string {
	return d.Encode()
}

// n returns 2 to the power of log N i.e d.ln.
func (d *ScryptDigest) n() (n int) {
	n = 2

	for i := 1; i < d.ln; i++ {
		n *= 2
	}

	return n
}
