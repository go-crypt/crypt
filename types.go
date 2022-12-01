package crypt

import (
	"database/sql/driver"
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// NewDigest wraps an algorithm.Digest in the convenience layer of the crypt.Digest.
func NewDigest(d algorithm.Digest) (digest *Digest, err error) {
	if d == nil {
		return nil, fmt.Errorf("can't create crypt.Digest from nil")
	}

	return &Digest{digest: d}, nil
}

// NewDigestDecode decodes a string into a algorithm.Digest and wraps it in the convenience layer of the crypt.Digest.
func NewDigestDecode(encodedDigest string) (digest *Digest, err error) {
	if len(encodedDigest) == 0 {
		return nil, fmt.Errorf("can't create crypt.Digest from empty string")
	}

	var d algorithm.Digest

	if d, err = Decode(encodedDigest); err != nil {
		return nil, err
	}

	return &Digest{digest: d}, nil
}

// NewNullDigest wraps an algorithm.Digest in the convenience layer of the crypt.NullDigest.
func NewNullDigest(d algorithm.Digest) (digest *NullDigest) {
	return &NullDigest{digest: d}
}

// NewNullDigestDecode decodes a string into a algorithm.Digest and wraps it in the convenience layer of the crypt.NullDigest.
func NewNullDigestDecode(encodedDigest string) (digest *NullDigest, err error) {
	if len(encodedDigest) == 0 {
		return &NullDigest{}, nil
	}

	var (
		d algorithm.Digest
	)

	if d, err = Decode(encodedDigest); err != nil {
		return nil, err
	}

	return &NullDigest{digest: d}, nil
}

// Digest is a decorator struct which wraps the algorithm.Digest and adds sql.Scanner/driver.Valuer,
// encoding.TextMarshaler/encoding.TextUnmarshaler, and encoding.BinaryMarshaler/encoding.BinaryUnmarshaler
// implementations.
type Digest struct {
	digest algorithm.Digest
}

// Encode decorates the algorithm.Digest Encode function.
func (d *Digest) Encode() string {
	return d.digest.Encode()
}

// String decorates the algorithm.Digest String function.
func (d *Digest) String() string {
	return d.digest.String()
}

// MatchBytes decorates the algorithm.Digest MatchBytes function.
func (d *Digest) MatchBytes(passwordBytes []byte) (match bool) {
	return d.digest.MatchBytes(passwordBytes)
}

// MatchAdvanced decorates the algorithm.Digest MatchAdvanced function.
func (d *Digest) MatchAdvanced(password string) (match bool, err error) {
	return d.digest.MatchAdvanced(password)
}

// MatchBytesAdvanced decorates the algorithm.Digest MatchBytesAdvanced function.
func (d *Digest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	return d.digest.MatchBytesAdvanced(passwordBytes)
}

// Match decorates the algorithm.Digest Match function.
func (d *Digest) Match(password string) (match bool) {
	return d.digest.Match(password)
}

// Value implements driver.Valuer.
func (d *Digest) Value() (value driver.Value, err error) {
	if d.digest == nil {
		return "", nil
	}

	return d.digest.Encode(), nil
}

// Scan implements sql.Scanner.
func (d *Digest) Scan(src any) (err error) {
	switch digest := src.(type) {
	case nil:
		return fmt.Errorf("invalid type for crypt.Digest: can't scan nil value into crypt.Digest: use crypt.NullDigest instead")
	case string:
		if d.digest, err = Decode(digest); err != nil {
			return err
		}

		return nil
	case byte:
		if d.digest, err = Decode(string(digest)); err != nil {
			return err
		}

		return nil
	default:
		return fmt.Errorf("invalid type for crypt.Digest: can't scan %T into crypt.Digest", digest)
	}
}

// MarshalText implements encoding.TextMarshaler.
func (d *Digest) MarshalText() (data []byte, err error) {
	if d.digest == nil {
		return []byte(""), nil
	}

	return []byte(d.digest.Encode()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Digest) UnmarshalText(data []byte) (err error) {
	if len(data) == 0 {
		return fmt.Errorf("can't unmarhsal empty data to crypt.Digest")
	}

	var digest algorithm.Digest

	if digest, err = Decode(string(data)); err != nil {
		return err
	}

	d.digest = digest

	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (d *Digest) MarshalBinary() (data []byte, err error) {
	return d.MarshalText()
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (d *Digest) UnmarshalBinary(data []byte) (err error) {
	return d.UnmarshalText(data)
}

// NullDigest is variation of crypt.Digest which accepts nulls.
type NullDigest struct {
	digest algorithm.Digest
}

// Encode decorates the algorithm.Digest Encode function.
func (d *NullDigest) Encode() string {
	if d.digest == nil {
		return ""
	}

	return d.digest.Encode()
}

// String decorates the algorithm.Digest String function.
func (d *NullDigest) String() string {
	if d.digest == nil {
		return ""
	}

	return d.digest.String()
}

// Match decorates the algorithm.Digest Match function.
func (d *NullDigest) Match(password string) (match bool) {
	if d.digest == nil {
		return false
	}

	return d.digest.Match(password)
}

// MatchBytes decorates the algorithm.Digest MatchBytes function.
func (d *NullDigest) MatchBytes(passwordBytes []byte) (match bool) {
	if d.digest == nil {
		return false
	}

	return d.digest.MatchBytes(passwordBytes)
}

// MatchAdvanced decorates the algorithm.Digest MatchAdvanced function.
func (d *NullDigest) MatchAdvanced(password string) (match bool, err error) {
	if d.digest == nil {
		return false, nil
	}

	return d.digest.MatchAdvanced(password)
}

// MatchBytesAdvanced decorates the algorithm.Digest MatchBytesAdvanced function.
func (d *NullDigest) MatchBytesAdvanced(passwordBytes []byte) (match bool, err error) {
	if d.digest == nil {
		return false, nil
	}

	return d.digest.MatchBytesAdvanced(passwordBytes)
}

// Value implements driver.Valuer.
func (d *NullDigest) Value() (value driver.Value, err error) {
	if d.digest == nil {
		return nil, nil
	}

	return d.digest.Encode(), nil
}

// Scan implements sql.Scanner.
func (d *NullDigest) Scan(src any) (err error) {
	switch digest := src.(type) {
	case nil:
		d.digest = nil

		return nil
	case string:
		if d.digest, err = Decode(digest); err != nil {
			return err
		}

		return nil
	case byte:
		if d.digest, err = Decode(string(digest)); err != nil {
			return err
		}

		return nil
	default:
		return fmt.Errorf("invalid type for crypt.Digest: can't scan %T into crypt.Digest", digest)
	}
}

// MarshalText implements encoding.TextMarshaler.
func (d *NullDigest) MarshalText() (data []byte, err error) {
	if d.digest == nil {
		return nil, nil
	}

	return []byte(d.digest.Encode()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *NullDigest) UnmarshalText(data []byte) (err error) {
	if len(data) == 0 {
		d.digest = nil

		return nil
	}

	var digest algorithm.Digest

	if digest, err = Decode(string(data)); err != nil {
		return err
	}

	d.digest = digest

	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (d *NullDigest) MarshalBinary() (data []byte, err error) {
	return d.MarshalText()
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (d *NullDigest) UnmarshalBinary(data []byte) (err error) {
	return d.UnmarshalText(data)
}
