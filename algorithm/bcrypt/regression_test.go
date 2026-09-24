package bcrypt

import (
	"strings"
	"testing"

	xbcrypt "github.com/go-crypt/x/bcrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-crypt/crypt/algorithm"
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
	testCases := []struct {
		cost, expected string
	}{
		{"04", "04"},
		{"05", "05"},
		{"09", "09"},
		{"31", "31"},
		{"4", "04"},
		{"9", "09"},
	}

	for _, tc := range testCases {
		t.Run(tc.cost, func(t *testing.T) {
			digest, err := Decode("$2b$" + tc.cost + "$" + validStandardKey)

			require.NoError(t, err)
			assert.Equal(t, "$2b$"+tc.expected+"$"+validStandardKey, digest.Encode())
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

func TestDecodePreservesVersionIdentifier(t *testing.T) {
	testCases := []string{
		"$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
		"$2b$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
		"$2x$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
		"$2y$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
		"$bcrypt-sha256$v=2,t=2a,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC",
		"$bcrypt-sha256$v=2,t=2b,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC",
		"$bcrypt-sha256$v=2,t=2x,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC",
		"$bcrypt-sha256$v=2,t=2y,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC",
	}

	for _, encoded := range testCases {
		t.Run(encoded, func(t *testing.T) {
			digest, err := Decode(encoded)
			require.NoError(t, err)

			assert.Equal(t, encoded, digest.Encode())
		})
	}
}

func TestHashedDigestsUseVersion2b(t *testing.T) {
	for _, variant := range []Variant{VariantStandard, VariantSHA256} {
		t.Run(variant.String(), func(t *testing.T) {
			hasher, err := New(WithVariant(variant), WithIterations(IterationsMin))
			require.NoError(t, err)

			digest, err := hasher.Hash("password")
			require.NoError(t, err)

			switch variant {
			case VariantSHA256:
				assert.Contains(t, digest.Encode(), "t=2b,")
			default:
				assert.Regexp(t, `^\$2b\$`, digest.Encode())
			}
		})
	}
}

func TestVersion2xMatchesASCIIPasswords(t *testing.T) {
	// The 2x version only differs from the other versions for passwords containing bytes with the high bit set.
	digest, err := Decode("$2x$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")
	require.NoError(t, err)

	match, err := digest.MatchAdvanced("U*U")
	assert.NoError(t, err)
	assert.True(t, match)

	match, err = digest.MatchAdvanced("U*V")
	assert.NoError(t, err)
	assert.False(t, match)
}

func TestVersion2xRejectsNonASCIIPasswords(t *testing.T) {
	// Reference vector from crypt_blowfish, which produced 2x digests using its sign extension bug.
	digest, err := Decode("$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e")
	require.NoError(t, err)

	match, err := digest.MatchAdvanced("\xa3")
	assert.False(t, match)
	assert.ErrorIs(t, err, algorithm.ErrPasswordInvalid)
	assert.EqualError(t, err, "bcrypt match error: password is invalid: the 2x version can't be verified for passwords containing non-ASCII bytes")

	assert.False(t, digest.Match("\xa3"))
}

func TestVersion2yMatchesNonASCIIPasswords(t *testing.T) {
	// Reference vector from crypt_blowfish.
	digest, err := Decode("$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq")
	require.NoError(t, err)

	match, err := digest.MatchAdvanced("\xa3")
	assert.NoError(t, err)
	assert.True(t, match)
}

func TestSHA256VariantVersion2xMatches(t *testing.T) {
	hasher, err := NewSHA256(WithIterations(IterationsMin))
	require.NoError(t, err)

	hashed, err := hasher.Hash("\xa3")
	require.NoError(t, err)

	encoded := strings.Replace(hashed.Encode(), ",t=2b,", ",t=2x,", 1)
	require.Contains(t, encoded, ",t=2x,")

	digest, err := Decode(encoded)
	require.NoError(t, err)

	match, err := digest.MatchAdvanced("\xa3")
	assert.NoError(t, err)
	assert.True(t, match)

	match, err = digest.MatchAdvanced("\xa4")
	assert.NoError(t, err)
	assert.False(t, match)
}

func TestDecodeSHA256VariantRequiresVersion2(t *testing.T) {
	testCases := []struct {
		name   string
		digest string
		err    string
	}{
		{"Version1", "$bcrypt-sha256$v=1,t=2b,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC", "bcrypt decode error: provided encoded hash has an invalid version: version 2 is supported but encoded hash is version 1"},
		{"Version3", "$bcrypt-sha256$v=3,t=2b,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC", "bcrypt decode error: provided encoded hash has an invalid version: version 2 is supported but encoded hash is version 3"},
		{"VersionEmpty", "$bcrypt-sha256$v=,t=2b,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC", "bcrypt decode error: provided encoded hash has an invalid version: version 2 is supported but encoded hash is version "},
		{"VersionMissing", "$bcrypt-sha256$t=2b,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC", "bcrypt decode error: provided encoded hash has an invalid version: version 2 is supported but encoded hash has no version"},
		{"PasslibVersion1Format", "$bcrypt-sha256$2a,12$LrmaIX5x4TRtAwEfwJZa1.$2ehnw6LvuIUTM0iz4iz9hTxv21B6KFO", "bcrypt decode error: parameter pair '2a' is not properly encoded: does not contain kv separator '='"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.digest)

			assert.Nil(t, digest)
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestDecodeSHA256VariantAcceptsVersion2(t *testing.T) {
	const encoded = "$bcrypt-sha256$v=2,t=2b,r=10$oYmTNJVOBi3hdhUYy4JqOe$jCuMDm.Pw9hhoF/FDC6sOi48yBAoWvC"

	digest, err := Decode(encoded)
	require.NoError(t, err)

	assert.Equal(t, encoded, digest.Encode())
	assert.True(t, digest.Match("password"))
}
