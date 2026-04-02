package pbkdf2

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
		{"ShouldReturnSHA1ForPbkdf2", "pbkdf2", VariantSHA1},
		{"ShouldReturnSHA1ForPbkdf2SHA1", "pbkdf2-sha1", VariantSHA1},
		{"ShouldReturnSHA1ForSHA1", "sha1", VariantSHA1},
		{"ShouldReturnSHA224", "pbkdf2-sha224", VariantSHA224},
		{"ShouldReturnSHA224ForName", "sha224", VariantSHA224},
		{"ShouldReturnSHA256", "pbkdf2-sha256", VariantSHA256},
		{"ShouldReturnSHA256ForName", "sha256", VariantSHA256},
		{"ShouldReturnSHA384", "pbkdf2-sha384", VariantSHA384},
		{"ShouldReturnSHA384ForName", "sha384", VariantSHA384},
		{"ShouldReturnSHA512", "pbkdf2-sha512", VariantSHA512},
		{"ShouldReturnSHA512ForName", "sha512", VariantSHA512},
		{"ShouldReturnNoneForUnknown", "unknown", VariantNone},
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
		{"ShouldReturnSHA1", VariantSHA1, "sha1"},
		{"ShouldReturnSHA224", VariantSHA224, "sha224"},
		{"ShouldReturnSHA256", VariantSHA256, "sha256"},
		{"ShouldReturnSHA384", VariantSHA384, "sha384"},
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
		{"ShouldReturnSHA1Prefix", VariantSHA1, "pbkdf2"},
		{"ShouldReturnSHA224Prefix", VariantSHA224, "pbkdf2-sha224"},
		{"ShouldReturnSHA256Prefix", VariantSHA256, "pbkdf2-sha256"},
		{"ShouldReturnSHA384Prefix", VariantSHA384, "pbkdf2-sha384"},
		{"ShouldReturnSHA512Prefix", VariantSHA512, "pbkdf2-sha512"},
		{"ShouldReturnEmptyForNone", VariantNone, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.Prefix())
		})
	}
}

func TestVariantHashFunc(t *testing.T) {
	testCases := []struct {
		name  string
		have  Variant
		isNil bool
	}{
		{"ShouldReturnSHA1HashFunc", VariantSHA1, false},
		{"ShouldReturnSHA256HashFunc", VariantSHA256, false},
		{"ShouldReturnSHA512HashFunc", VariantSHA512, false},
		{"ShouldReturnNilForNone", VariantNone, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hf := tc.have.HashFunc()

			if tc.isNil {
				assert.Nil(t, hf)
			} else {
				assert.NotNil(t, hf)
			}
		})
	}
}

func TestVariantDefaultIterations(t *testing.T) {
	testCases := []struct {
		name     string
		have     Variant
		expected int
	}{
		{"ShouldReturnSHA1Default", VariantSHA1, 720000},
		{"ShouldReturnSHA224Default", VariantSHA224, 720000},
		{"ShouldReturnSHA256Default", VariantSHA256, 310000},
		{"ShouldReturnSHA384Default", VariantSHA384, 310000},
		{"ShouldReturnSHA512Default", VariantSHA512, 120000},
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
		{"ShouldNotErrNone", VariantNone, ""},
		{"ShouldErrInvalid", Variant(99), "pbkdf2 validation error: parameter is invalid: variant '99' is invalid"},
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
		{"ShouldNotErrEmpty", "", ""},
		{"ShouldErrInvalid", "invalid", "pbkdf2 validation error: parameter is invalid: variant identifier 'invalid' is invalid"},
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
		{"ShouldNotErrMin", 100000, ""},
		{"ShouldErrBelowMin", 99999, "pbkdf2 validation error: parameter is invalid: parameter 'iterations' must be between 100000 and 2147483647 but is set to '99999'"},
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
		{"ShouldNotErrMin", 8, ""},
		{"ShouldNotErr16", 16, ""},
		{"ShouldErrBelowMin", 7, "pbkdf2 validation error: parameter is invalid: parameter 'salt length' must be between 8 and 2147483647 but is set to '7'"},
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

func TestWithKeyLength(t *testing.T) {
	testCases := []struct {
		name string
		have int
		err  string
	}{
		{"ShouldNotErr32", 32, ""},
		{"ShouldErrWithoutVariant", 32, "pbkdf2 validation error: tag size must not be set before the variant is set"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}

			if tc.name == "ShouldNotErr32" {
				h.variant = VariantSHA256
			}

			err := WithKeyLength(tc.have)(h)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDigestMatchAdvancedAndString(t *testing.T) {
	hasher, err := NewSHA256(WithIterations(100000))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	match, err := digest.MatchAdvanced("password")
	assert.NoError(t, err)
	assert.True(t, match)

	assert.Equal(t, digest.Encode(), digest.String())
}

func TestNewSHA224(t *testing.T) {
	hasher, err := NewSHA224()

	assert.NoError(t, err)
	assert.NotNil(t, hasher)
}

func TestNewSHA384(t *testing.T) {
	hasher, err := NewSHA384()

	assert.NoError(t, err)
	assert.NotNil(t, hasher)
}

func TestNew(t *testing.T) {
	hasher, err := New()

	assert.NoError(t, err)
	assert.NotNil(t, hasher)
}

func TestNewSHA1(t *testing.T) {
	hasher, err := NewSHA1()

	assert.NoError(t, err)
	assert.NotNil(t, hasher)
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
	hasher, err := NewSHA256(WithIterations(100000))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	encoded := digest.Encode()
	assert.Contains(t, encoded, "$pbkdf2-sha256$")

	decoded, err := Decode(encoded)
	require.NoError(t, err)

	assert.True(t, decoded.Match("password"))
	assert.False(t, decoded.Match("wrong"))
}

func TestHashWithSalt(t *testing.T) {
	testCases := []struct {
		name string
		salt []byte
		err  string
	}{
		{"ShouldNotErrValidSalt", make([]byte, 16), ""},
		{"ShouldErrSaltTooShort", make([]byte, 7), "pbkdf2 hashing error: salt is invalid: salt bytes must have a length of between 8 and 2147483647 but has a length of 7"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := NewSHA256(WithIterations(100000))
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
	hasher, err := NewSHA256(WithIterations(100000))
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
		{"ShouldFailInvalidFormat", "$", "pbkdf2 decode error: provided encoded hash has an invalid format"},
		{"ShouldFailUnknownIdentifier", "$unknown$100000$salt$key", "pbkdf2 decode error: provided encoded hash has an invalid identifier: identifier 'unknown' is not an encoded pbkdf2 digest"},
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
	hasher, err := NewSHA256(WithIterations(100000))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	d, ok := digest.(*Digest)
	require.True(t, ok)

	assert.NotEmpty(t, d.Key())
	assert.NotEmpty(t, d.Salt())
}

func TestDigestMatch(t *testing.T) {
	hasher, err := NewSHA256(WithIterations(100000))
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
