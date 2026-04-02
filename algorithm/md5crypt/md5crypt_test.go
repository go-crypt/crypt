package md5crypt

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
		{"ShouldReturnStandardFor1", "1", VariantStandard},
		{"ShouldReturnStandardForMd5crypt", "md5crypt", VariantStandard},
		{"ShouldReturnStandardForStandard", "standard", VariantStandard},
		{"ShouldReturnStandardForCommon", "common", VariantStandard},
		{"ShouldReturnSunForMd5", "md5", VariantSun},
		{"ShouldReturnSunForSun", "sun", VariantSun},
		{"ShouldReturnNoneForUnknown", "unknown", VariantNone},
		{"ShouldReturnNoneForEmpty", "", VariantNone},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, NewVariant(tc.have))
		})
	}
}

func TestVariantString(t *testing.T) {
	testCases := []struct {
		name     string
		have     Variant
		expected string
	}{
		{"ShouldReturnStandard", VariantStandard, "standard"},
		{"ShouldReturnSun", VariantSun, "sun"},
		{"ShouldReturnEmptyForNone", VariantNone, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.String())
		})
	}
}

func TestVariantPrefix(t *testing.T) {
	testCases := []struct {
		name     string
		have     Variant
		expected string
	}{
		{"ShouldReturnStandardPrefix", VariantStandard, "1"},
		{"ShouldReturnSunPrefix", VariantSun, "md5"},
		{"ShouldReturnEmptyForNone", VariantNone, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.Prefix())
		})
	}
}

func TestWithVariant(t *testing.T) {
	testCases := []struct {
		name string
		have Variant
		err  string
	}{
		{"ShouldNotErrStandard", VariantStandard, ""},
		{"ShouldNotErrSun", VariantSun, ""},
		{"ShouldNotErrNone", VariantNone, ""},
		{"ShouldErrInvalid", Variant(99), "md5crypt validation error: parameter is invalid: variant '99' is invalid"},
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
		{"ShouldNotErrStandard", "standard", ""},
		{"ShouldNotErrSun", "sun", ""},
		{"ShouldNotErrEmpty", "", ""},
		{"ShouldErrInvalid", "invalid", "md5crypt validation error: parameter is invalid: variant identifier 'invalid' is invalid"},
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

func TestWithSaltLength(t *testing.T) {
	testCases := []struct {
		name string
		have int
		err  string
	}{
		{"ShouldNotErrMin", 1, ""},
		{"ShouldNotErrMax", 8, ""},
		{"ShouldErrBelowMin", 0, "md5crypt validation error: parameter is invalid: parameter 'salt length' must be between 1 and 8 but is set to '0'"},
		{"ShouldErrAboveMax", 9, "md5crypt validation error: parameter is invalid: parameter 'salt length' must be between 1 and 8 but is set to '9'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := WithSaltLength(tc.have)(h)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestWithIterations(t *testing.T) {
	h := &Hasher{}
	err := WithIterations(34000)(h)

	assert.NoError(t, err)
	assert.Equal(t, uint32(34000), h.iterations)
}

func TestWithRounds(t *testing.T) {
	h := &Hasher{}
	err := WithRounds(1000)(h)

	assert.NoError(t, err)
	assert.Equal(t, uint32(1000), h.iterations)
}

func TestDigestMatchAdvanced(t *testing.T) {
	hasher, err := New()
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	match, err := digest.MatchAdvanced("password")
	assert.NoError(t, err)
	assert.True(t, match)
}

func TestNew(t *testing.T) {
	testCases := []struct {
		name string
		opts []Opt
		err  string
	}{
		{"ShouldNotErrDefaults", nil, ""},
		{"ShouldNotErrSun", []Opt{WithVariant(VariantSun)}, ""},
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

func TestHashAndDecode(t *testing.T) {
	testCases := []struct {
		name           string
		opts           []Opt
		password       string
		expectedPrefix string
	}{
		{"ShouldHashStandard", nil, "password", "$1$"},
		{"ShouldHashSun", []Opt{WithVariant(VariantSun)}, "password", "$md5"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := New(tc.opts...)
			require.NoError(t, err)

			digest, err := hasher.Hash(tc.password)
			require.NoError(t, err)

			encoded := digest.Encode()
			assert.Contains(t, encoded, tc.expectedPrefix)

			decoded, err := Decode(encoded)
			require.NoError(t, err)

			assert.True(t, decoded.Match(tc.password))
			assert.False(t, decoded.Match("wrong"))
		})
	}
}

func TestHashWithSalt(t *testing.T) {
	testCases := []struct {
		name string
		salt []byte
		err  string
	}{
		{"ShouldNotErrValidSalt", []byte("abcdefgh"), ""},
		{"ShouldErrSaltTooLong", []byte("abcdefghi"), "md5crypt hashing error: salt is invalid: salt bytes must have a length of between 1 and 8 but has a length of 9"},
		{"ShouldErrSaltTooShort", []byte{}, "md5crypt hashing error: salt is invalid: salt bytes must have a length of between 1 and 8 but has a length of 0"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := New()
			require.NoError(t, err)

			digest, err := hasher.HashWithSalt("password", tc.salt)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.NotNil(t, digest)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
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
		{"ShouldFailInvalidFormat", "$", "md5crypt decode error: provided encoded hash has an invalid format"},
		{"ShouldFailEmptyString", "", "md5crypt decode error: provided encoded hash has an invalid format"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDigestKeySalt(t *testing.T) {
	hasher, err := New()
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	d, ok := digest.(*Digest)
	require.True(t, ok)

	assert.NotEmpty(t, d.Key())
	assert.NotEmpty(t, d.Salt())
}

func TestDigestMatch(t *testing.T) {
	hasher, err := New()
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	testCases := []struct {
		name     string
		password string
		expected bool
	}{
		{"ShouldMatchCorrect", "password", true},
		{"ShouldNotMatchWrong", "wrong", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, digest.Match(tc.password))
		})
	}
}

func TestDigestEncode(t *testing.T) {
	hasher, err := New()
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	encoded := digest.Encode()
	assert.NotEmpty(t, encoded)
	assert.Equal(t, encoded, digest.String())
}
