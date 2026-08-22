package bcrypt

import (
	"testing"

	xbcrypt "github.com/go-crypt/x/bcrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeRejectsUnusableCost(t *testing.T) {
	testCases := []struct {
		name   string
		digest string
	}{
		{"StandardNegative", "$2b$-1$" + validStandardKey},
		{"StandardZero", "$2b$00$" + validStandardKey},
		{"StandardBelowMinimum", "$2b$03$" + validStandardKey},
		{"StandardAboveMaximum", "$2b$99$" + validStandardKey},
		{"SHA256Zero", "$bcrypt-sha256$v=2,t=2b,r=0$" + validSHA256Salt + "$" + validSHA256Key},
		{"SHA256AboveMaximum", "$bcrypt-sha256$v=2,t=2b,r=99$" + validSHA256Salt + "$" + validSHA256Key},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.digest)

			assert.Nil(t, digest)
			assert.Error(t, err)
		})
	}
}

func TestDecodeAcceptsLegacyCosts(t *testing.T) {
	for _, cost := range []string{"04", "05", "09", "31"} {
		t.Run(cost, func(t *testing.T) {
			encoded := "$2b$" + cost + "$" + validStandardKey

			digest, err := Decode(encoded)

			require.NoError(t, err)
			assert.Equal(t, encoded, digest.Encode())
		})
	}
}

func TestDecodeAcceptsEveryCostTheKeyDerivationAccepts(t *testing.T) {
	assert.NoError(t, validateCost(xbcrypt.MinCost))
	assert.NoError(t, validateCost(xbcrypt.MaxCost))
	assert.Error(t, validateCost(xbcrypt.MinCost-1))
	assert.Error(t, validateCost(xbcrypt.MaxCost+1))
}

func TestHashedDigestsRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		new  func() (*Hasher, error)
	}{
		{"Standard", func() (*Hasher, error) { return New(WithCost(IterationsMin)) }},
		{"SHA256", func() (*Hasher, error) { return NewSHA256(WithCost(IterationsMin)) }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := tc.new()
			require.NoError(t, err)
			require.NoError(t, hasher.Validate())

			digest, err := hasher.Hash("password")
			require.NoError(t, err)

			encoded := digest.Encode()

			decoded, err := Decode(encoded)
			require.NoError(t, err, "encoded digest %q could not be decoded", encoded)

			assert.Equal(t, encoded, decoded.Encode())
			assert.True(t, decoded.Match("password"))
			assert.False(t, decoded.Match("incorrect"))
		})
	}
}

func TestSHA256VariantIsNotLimitedTo72Bytes(t *testing.T) {
	long := make([]byte, 200)

	for i := range long {
		long[i] = byte('a' + i%26)
	}

	hasher, err := NewSHA256(WithCost(IterationsMin))
	require.NoError(t, err)

	digest, err := hasher.Hash(string(long))
	require.NoError(t, err)

	assert.True(t, digest.MatchBytes(long))

	truncated := append(append([]byte{}, long[:72]...), []byte("different")...)

	assert.False(t, digest.MatchBytes(truncated))
}

const (
	validStandardKey = "3XCpXfcQBjcbXFHTLcbFju0KNQ2ipfeNbcH8b7ZgIkXlbNkYbGDWm"
	validSHA256Salt  = "3XCpXfcQBjcbXFHTLcbFju"
	validSHA256Key   = "AXNZ1B7NPTf7XyCqUKcvIUOB5eKKZ4C"
)
