package shacrypt

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
		{"ShouldReturnSHA256ForIdentifier", "5", VariantSHA256},
		{"ShouldReturnSHA256ForName", "sha256", VariantSHA256},
		{"ShouldReturnSHA512ForIdentifier", "6", VariantSHA512},
		{"ShouldReturnSHA512ForName", "sha512", VariantSHA512},
		{"ShouldDefaultToSHA512ForUnknown", "unknown", VariantSHA512},
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
		{"ShouldReturnSHA256", VariantSHA256, "sha256"},
		{"ShouldReturnSHA512", VariantSHA512, "sha512"},
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
		{"ShouldReturnSHA256Prefix", VariantSHA256, "5"},
		{"ShouldReturnSHA512Prefix", VariantSHA512, "6"},
		{"ShouldDefaultToSHA512ForNone", VariantNone, "6"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.Prefix())
		})
	}
}

func TestVariantHashFunc(t *testing.T) {
	testCases := []struct {
		name string
		have Variant
	}{
		{"ShouldReturnSHA256HashFunc", VariantSHA256},
		{"ShouldReturnSHA512HashFunc", VariantSHA512},
		{"ShouldReturnDefaultHashFunc", VariantNone},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotNil(t, tc.have.HashFunc())
		})
	}
}

func TestVariantDefaultIterations(t *testing.T) {
	testCases := []struct {
		name     string
		have     Variant
		expected int
	}{
		{"ShouldReturnSHA256Default", VariantSHA256, 1000000},
		{"ShouldReturnSHA512Default", VariantSHA512, 500000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.DefaultIterations())
		})
	}
}

func TestWithVariant(t *testing.T) {
	testCases := []struct {
		name string
		have Variant
		err  string
	}{
		{"ShouldNotErrSHA256", VariantSHA256, ""},
		{"ShouldNotErrSHA512", VariantSHA512, ""},
		{"ShouldNotErrNone", VariantNone, ""},
		{"ShouldErrInvalid", Variant(99), "shacrypt validation error: parameter is invalid: variant '99' is invalid"},
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
		{"ShouldNotErrSHA256", "sha256", ""},
		{"ShouldNotErrSHA512", "sha512", ""},
		{"ShouldNotErrEmpty", "", ""},
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

func TestWithSHA256(t *testing.T) {
	h := &Hasher{}
	err := WithSHA256()(h)

	assert.NoError(t, err)
	assert.Equal(t, VariantSHA256, h.variant)
}

func TestWithSHA512(t *testing.T) {
	h := &Hasher{}
	err := WithSHA512()(h)

	assert.NoError(t, err)
	assert.Equal(t, VariantSHA512, h.variant)
}

func TestWithIterations(t *testing.T) {
	testCases := []struct {
		name string
		have int
		err  string
	}{
		{"ShouldNotErrMin", 1000, ""},
		{"ShouldNotErrMax", 999999999, ""},
		{"ShouldErrBelowMin", 999, "shacrypt validation error: parameter is invalid: parameter 'iterations' must be between 1000 and 999999999 but is set to '999'"},
		{"ShouldErrAboveMax", 1000000000, "shacrypt validation error: parameter is invalid: parameter 'iterations' must be between 1000 and 999999999 but is set to '1000000000'"},
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

func TestWithSaltLength(t *testing.T) {
	testCases := []struct {
		name string
		have int
		err  string
	}{
		{"ShouldNotErrMin", 1, ""},
		{"ShouldNotErrMax", 16, ""},
		{"ShouldErrBelowMin", 0, "shacrypt validation error: parameter is invalid: parameter 'salt length' must be between 1 and 16 but is set to '0'"},
		{"ShouldErrAboveMax", 17, "shacrypt validation error: parameter is invalid: parameter 'salt length' must be between 1 and 16 but is set to '17'"},
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

func TestWithRounds(t *testing.T) {
	h := &Hasher{}
	err := WithRounds(5000)(h)

	assert.NoError(t, err)
	assert.Equal(t, 5000, h.iterations)
}

func TestVariantName(t *testing.T) {
	testCases := []struct {
		name     string
		have     Variant
		expected string
	}{
		{"ShouldReturnSHA256Name", VariantSHA256, "sha256"},
		{"ShouldReturnSHA512Name", VariantSHA512, "sha512"},
		{"ShouldReturnDefaultName", VariantNone, "sha512"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.Name())
		})
	}
}

func TestDigestMatchAdvancedAndString(t *testing.T) {
	hasher, err := New(WithIterations(1000))
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
		{"ShouldNotErrSHA256", []Opt{WithVariant(VariantSHA256)}, ""},
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

func TestNewSHA512(t *testing.T) {
	hasher, err := NewSHA512()

	assert.NoError(t, err)
	assert.NotNil(t, hasher)
}

func TestHashAndDecode(t *testing.T) {
	testCases := []struct {
		name           string
		opts           []Opt
		password       string
		expectedPrefix string
	}{
		{"ShouldHashSHA256", []Opt{WithVariant(VariantSHA256), WithIterations(1000)}, "password", "$5$"},
		{"ShouldHashSHA512", []Opt{WithVariant(VariantSHA512), WithIterations(1000)}, "password", "$6$"},
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
		{"ShouldNotErrValidSalt", []byte("abcdefghijklmnop"), ""},
		{"ShouldErrSaltTooLong", make([]byte, 17), "shacrypt hashing error: salt is invalid: salt bytes must have a length of between 1 and 16 but has a length of 17"},
		{"ShouldErrSaltTooShort", []byte{}, "shacrypt hashing error: salt is invalid: salt bytes must have a length of between 1 and 16 but has a length of 0"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := New(WithIterations(1000))
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
	hasher, err := New(WithIterations(1000))
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
		{"ShouldFailInvalidFormat", "$", "shacrypt decode error: provided encoded hash has an invalid format"},
		{"ShouldFailTooFewParts", "$5$", "shacrypt decode error: provided encoded hash has an invalid format"},
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
	hasher, err := New(WithIterations(1000))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	d, ok := digest.(*Digest)
	require.True(t, ok)

	assert.NotEmpty(t, d.Key())
	assert.NotEmpty(t, d.Salt())
}

func TestDigestMatch(t *testing.T) {
	hasher, err := New(WithIterations(1000))
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
