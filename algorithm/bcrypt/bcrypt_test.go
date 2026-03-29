package bcrypt

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
		{"ShouldReturnStandardFor2b", "2b", VariantStandard},
		{"ShouldReturnStandardFor2a", "2a", VariantStandard},
		{"ShouldReturnStandardFor2x", "2x", VariantStandard},
		{"ShouldReturnStandardFor2y", "2y", VariantStandard},
		{"ShouldReturnStandardForEmpty", "", VariantStandard},
		{"ShouldReturnStandardForStandard", "standard", VariantStandard},
		{"ShouldReturnStandardForCommon", "common", VariantStandard},
		{"ShouldReturnSHA256", "bcrypt-sha256", VariantSHA256},
		{"ShouldReturnSHA256ForName", "sha256", VariantSHA256},
		{"ShouldReturnNoneForUnknown", "nope", VariantNone},
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
		{"ShouldReturnSHA256", VariantSHA256, "sha256"},
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
		{"ShouldReturnStandardPrefix", VariantStandard, "2b"},
		{"ShouldReturnSHA256Prefix", VariantSHA256, "bcrypt-sha256"},
		{"ShouldReturnEmptyForNone", VariantNone, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.Prefix())
		})
	}
}

func TestVariantPasswordMaxLength(t *testing.T) {
	testCases := []struct {
		name     string
		have     Variant
		expected int
	}{
		{"ShouldReturnStandardMax", VariantStandard, 72},
		{"ShouldReturnSHA256NoLimit", VariantSHA256, -1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.PasswordMaxLength())
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
		{"ShouldNotErrSHA256", VariantSHA256, ""},
		{"ShouldNotErrNone", VariantNone, ""},
		{"ShouldErrInvalid", Variant(99), "bcrypt validation error: parameter is invalid: variant '99' is invalid"},
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
		{"ShouldNotErrSHA256", "sha256", ""},
		{"ShouldNotErrEmpty", "", ""},
		{"ShouldErrInvalid", "invalid", "bcrypt validation error: parameter is invalid: variant identifier 'invalid' is invalid"},
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

func TestWithIterations(t *testing.T) {
	testCases := []struct {
		name string
		have int
		err  string
	}{
		{"ShouldNotErrMin", 10, ""},
		{"ShouldNotErrMax", 31, ""},
		{"ShouldErrBelowMin", 9, "bcrypt validation error: parameter is invalid: parameter 'iterations' must be between 10 and 31 but is set to '9'"},
		{"ShouldErrAboveMax", 32, "bcrypt validation error: parameter is invalid: parameter 'iterations' must be between 10 and 31 but is set to '32'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := WithIterations(tc.have)(h)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestWithCost(t *testing.T) {
	h := &Hasher{}
	err := WithCost(10)(h)

	assert.NoError(t, err)
	assert.Equal(t, 10, h.iterations)
}

func TestDigestMatchAdvancedAndString(t *testing.T) {
	hasher, err := New(WithIterations(10))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	match, err := digest.MatchAdvanced("password")
	assert.NoError(t, err)
	assert.True(t, match)

	assert.Equal(t, digest.Encode(), digest.String())
}

func TestNew(t *testing.T) {
	testCases := []struct {
		name string
		opts []Opt
		err  string
	}{
		{"ShouldNotErrDefaults", nil, ""},
		{"ShouldNotErrWithIterations", []Opt{WithIterations(10)}, ""},
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

func TestNewSHA256(t *testing.T) {
	hasher, err := NewSHA256()

	assert.NoError(t, err)
	assert.NotNil(t, hasher)
}

func TestHashAndDecode(t *testing.T) {
	testCases := []struct {
		name           string
		setup          func() (*Hasher, error)
		password       string
		expectedPrefix string
	}{
		{
			"ShouldHashStandard",
			func() (*Hasher, error) { return New(WithIterations(10)) },
			"password",
			"$2b$",
		},
		{
			"ShouldHashSHA256",
			func() (*Hasher, error) { return NewSHA256(WithIterations(10)) },
			"password",
			"$bcrypt-sha256$",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := tc.setup()
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
		{"ShouldNotErrValidSalt", make([]byte, 16), ""},
		{"ShouldErrInvalidSaltLength", make([]byte, 8), "bcrypt hashing error: salt is invalid: salt size must be 16 bytes but it's 8 bytes"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := New(WithIterations(10))
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
	hasher, err := New(WithIterations(10))
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
		{"ShouldFailInvalidFormat", "$", "bcrypt decode error: provided encoded hash has an invalid format"},
		{"ShouldFailTooFewParts", "$2b$", "bcrypt decode error: provided encoded hash has an invalid format"},
		{"ShouldFailUnknownIdentifier", "$unknown$10$abc", "bcrypt decode error: provided encoded hash has an invalid identifier: identifier 'unknown' is not an encoded bcrypt digest"},
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

func TestDigestMatch(t *testing.T) {
	hasher, err := New(WithIterations(10))
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
