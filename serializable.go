package crypt

import (
	"bytes"
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

func NewSerializableDigest(digest algorithm.Digest) *SerializableDigest {
	return &SerializableDigest{digest: digest}
}

// SerializableDigest is a algorithm.Digest which can be Marshalled or Unmarshalled. Currently supports
// JSON.
type SerializableDigest struct {
	digest algorithm.Digest
}

func (d *SerializableDigest) String() string {
	return d.digest.String()
}

func (d *SerializableDigest) Match(password string) (match bool) {
	return d.digest.Match(password)
}

func (d *SerializableDigest) MatchBytes(passwordBytes []byte) (match bool) {
	return d.digest.MatchBytes(passwordBytes)
}

func (d *SerializableDigest) MatchAdvanced(password string) (match bool, err error) {
	return d.digest.MatchAdvanced(password)
}

func (d *SerializableDigest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	return d.digest.MatchBytesAdvanced(passwordBytes)
}

func (d *SerializableDigest) Encode() (hash string) {
	return d.digest.Encode()
}

func (d *SerializableDigest) UnmarshalJSON(data []byte) (err error) {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}

	if d.digest, err = Decode(string(bytes.Trim(data, `"`))); err != nil {
		return err
	}

	return nil
}

func (d *SerializableDigest) MarshalJSON() (data []byte, err error) {
	if d == nil || d.digest == nil {
		return []byte("null"), nil
	}

	return []byte(fmt.Sprintf("\"%s\"", d.digest.Encode())), nil
}
