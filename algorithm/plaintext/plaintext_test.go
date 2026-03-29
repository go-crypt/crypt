package plaintext

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVariant(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected Variant
	}{
		{
			"ShouldReturnVariantPlainText",
			"plaintext",
			VariantPlainText,
		},
		{
			"ShouldReturnVariantBase64",
			"base64",
			VariantBase64,
		},
		{
			"ShouldReturnVariantNoneForUnknown",
			"unknown",
			VariantNone,
		},
		{
			"ShouldReturnVariantNoneForEmpty",
			"",
			VariantNone,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := NewVariant(tc.have)

			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestVariantPrefix(t *testing.T) {
	testCases := []struct {
		name     string
		have     Variant
		expected string
	}{
		{
			"ShouldReturnPlainTextPrefix",
			VariantPlainText,
			"plaintext",
		},
		{
			"ShouldReturnBase64Prefix",
			VariantBase64,
			"base64",
		},
		{
			"ShouldReturnEmptyForNone",
			VariantNone,
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.have.Prefix()

			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestVariantEncodeDecode(t *testing.T) {
	testCases := []struct {
		name    string
		variant Variant
		have    []byte
	}{
		{
			"ShouldRoundTripPlainText",
			VariantPlainText,
			[]byte("password"),
		},
		{
			"ShouldRoundTripBase64",
			VariantBase64,
			[]byte("password"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := tc.variant.Encode(tc.have)
			decoded, err := tc.variant.Decode(encoded)

			require.NoError(t, err)
			assert.Equal(t, tc.have, decoded)
		})
	}
}

func TestWithVariant(t *testing.T) {
	testCases := []struct {
		name string
		have Variant
		err  string
	}{
		{
			"ShouldNotErrPlainText",
			VariantPlainText,
			"",
		},
		{
			"ShouldNotErrBase64",
			VariantBase64,
			"",
		},
		{
			"ShouldNotErrNone",
			VariantNone,
			"",
		},
		{
			"ShouldErrInvalidVariant",
			Variant(99),
			"plaintext validation error: parameter is invalid: variant '99' is invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := WithVariant(tc.have)(h)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestWithVariantName(t *testing.T) {
	testCases := []struct {
		name string
		have string
		err  string
	}{
		{
			"ShouldNotErrPlainText",
			"plaintext",
			"",
		},
		{
			"ShouldNotErrBase64",
			"base64",
			"",
		},
		{
			"ShouldNotErrEmpty",
			"",
			"",
		},
		{
			"ShouldErrUnknown",
			"unknown",
			"plaintext validation error: parameter is invalid: variant identifier 'unknown' is invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := WithVariantName(tc.have)(h)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestNew(t *testing.T) {
	testCases := []struct {
		name string
		opts []Opt
		err  string
	}{
		{
			"ShouldNotErrDefaults",
			nil,
			"",
		},
		{
			"ShouldNotErrBase64",
			[]Opt{WithVariant(VariantBase64)},
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := New(tc.opts...)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.NotNil(t, hasher)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestHash(t *testing.T) {
	testCases := []struct {
		name           string
		opts           []Opt
		password       string
		expectedPrefix string
	}{
		{
			"ShouldHashPlainText",
			nil,
			"password",
			"$plaintext$",
		},
		{
			"ShouldHashBase64",
			[]Opt{WithVariant(VariantBase64)},
			"password",
			"$base64$",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := New(tc.opts...)
			require.NoError(t, err)

			digest, err := hasher.Hash(tc.password)
			require.NoError(t, err)

			encoded := digest.Encode()
			assert.Contains(t, encoded, tc.expectedPrefix)
		})
	}
}

func TestHashWithSalt(t *testing.T) {
	hasher, err := New()
	require.NoError(t, err)

	digest, err := hasher.HashWithSalt("password", []byte("ignored"))
	require.NoError(t, err)

	assert.True(t, digest.Match("password"))
}

func TestMustHash(t *testing.T) {
	hasher, err := New()
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		digest := hasher.MustHash("password")
		assert.True(t, digest.Match("password"))
	})
}

func TestDecode(t *testing.T) {
	testCases := []struct {
		name string
		have string
		err  string
	}{
		{
			"ShouldDecodePlainText",
			"$plaintext$password",
			"",
		},
		{
			"ShouldDecodeBase64",
			"$base64$cGFzc3dvcmQ",
			"",
		},
		{
			"ShouldFailUnknownIdentifier",
			"$unknown$x",
			"plaintext decode error: provided encoded hash has an invalid identifier: identifier 'unknown' is not an encoded plaintext digest",
		},
		{
			"ShouldFailTooFewParts",
			"$",
			"plaintext decode error: provided encoded hash has an invalid format",
		},
		{
			"ShouldFailEmptyString",
			"",
			"plaintext decode error: provided encoded hash has an invalid format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.NotNil(t, digest)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDecodeVariant(t *testing.T) {
	testCases := []struct {
		name    string
		variant Variant
		have    string
		err     string
	}{
		{
			"ShouldDecodePlainTextVariant",
			VariantPlainText,
			"$plaintext$password",
			"",
		},
		{
			"ShouldFailWrongVariant",
			VariantBase64,
			"$plaintext$password",
			"plaintext decode error: the 'plaintext' variant cannot be decoded only the 'base64' variant can be",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := DecodeVariant(tc.variant)(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.NotNil(t, digest)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDigestMatch(t *testing.T) {
	testCases := []struct {
		name     string
		digest   *Digest
		password string
		expected bool
	}{
		{
			"ShouldMatchPlainTextCorrect",
			&Digest{variant: VariantPlainText, key: []byte("password")},
			"password",
			true,
		},
		{
			"ShouldNotMatchPlainTextWrong",
			&Digest{variant: VariantPlainText, key: []byte("password")},
			"wrong",
			false,
		},
		{
			"ShouldMatchBase64Correct",
			&Digest{variant: VariantBase64, key: []byte("password")},
			"password",
			true,
		},
		{
			"ShouldNotMatchBase64Wrong",
			&Digest{variant: VariantBase64, key: []byte("password")},
			"wrong",
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.digest.Match(tc.password))
			assert.Equal(t, tc.expected, tc.digest.MatchBytes([]byte(tc.password)))

			match, err := tc.digest.MatchAdvanced(tc.password)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, match)

			match, err = tc.digest.MatchBytesAdvanced([]byte(tc.password))
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, match)
		})
	}
}

func TestDigestMatchAdvancedEmptyKey(t *testing.T) {
	d := &Digest{variant: VariantPlainText, key: nil}

	match, err := d.MatchAdvanced("password")
	assert.False(t, match)
	assert.EqualError(t, err, "plaintext match error: password is invalid: key has 0 bytes")
}

func TestDigestEncode(t *testing.T) {
	testCases := []struct {
		name     string
		digest   Digest
		expected string
	}{
		{
			"ShouldEncodePlainText",
			NewDigest("password"),
			"$plaintext$password",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.digest.Encode())
			assert.Equal(t, tc.expected, tc.digest.String())
		})
	}
}

func TestDigestKey(t *testing.T) {
	d := NewDigest("password")
	assert.Equal(t, []byte("password"), d.Key())
}

func TestNewDigest(t *testing.T) {
	d := NewDigest("password")
	assert.Equal(t, VariantPlainText, d.variant)
	assert.Equal(t, []byte("password"), d.key)
}

func TestNewBase64Digest(t *testing.T) {
	d := NewBase64Digest("password")
	assert.Equal(t, VariantBase64, d.variant)
	assert.Equal(t, []byte("password"), d.key)
}
