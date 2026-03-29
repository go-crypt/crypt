package scrypt

import (
	"fmt"
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
		{"ShouldReturnScrypt", "scrypt", VariantScrypt},
		{"ShouldReturnYescrypt", "yescrypt", VariantYescrypt},
		{"ShouldReturnYescryptForY", "y", VariantYescrypt},
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
		{"ShouldReturnScrypt", VariantScrypt, "scrypt"},
		{"ShouldReturnYescrypt", VariantYescrypt, "y"},
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
		{"ShouldReturnScryptPrefix", VariantScrypt, "scrypt"},
		{"ShouldReturnYescryptPrefix", VariantYescrypt, "y"},
		{"ShouldReturnEmptyForNone", VariantNone, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.Prefix())
		})
	}
}

func TestVariantKeyFunc(t *testing.T) {
	testCases := []struct {
		name  string
		have  Variant
		isNil bool
	}{
		{"ShouldReturnScryptKeyFunc", VariantScrypt, false},
		{"ShouldReturnYescryptKeyFunc", VariantYescrypt, false},
		{"ShouldReturnNilForNone", VariantNone, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kf := tc.have.KeyFunc()

			if tc.isNil {
				assert.Nil(t, kf)
			} else {
				assert.NotNil(t, kf)
			}
		})
	}
}

func TestWithVariant(t *testing.T) {
	testCases := []struct {
		name string
		have Variant
		err  string
	}{
		{"ShouldNotErrScrypt", VariantScrypt, ""},
		{"ShouldNotErrYescrypt", VariantYescrypt, ""},
		{"ShouldNotErrNone", VariantNone, ""},
		{"ShouldErrInvalid", Variant(99), "scrypt validation error: parameter is invalid: variant '99' is invalid"},
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
		{"ShouldNotErrScrypt", "scrypt", ""},
		{"ShouldNotErrEmpty", "", ""},
		{"ShouldErrInvalid", "invalid", "scrypt validation error: parameter is invalid: variant identifier 'invalid' is invalid"},
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

func TestWithLN(t *testing.T) {
	testCases := []struct {
		name string
		have int
		err  string
	}{
		{"ShouldNotErrMin", 1, ""},
		{"ShouldNotErrMax", 58, ""},
		{"ShouldErrBelowMin", 0, "scrypt validation error: parameter is invalid: parameter 'iterations' must be between 1 and 58 but is set to '0'"},
		{"ShouldErrAboveMax", 59, "scrypt validation error: parameter is invalid: parameter 'iterations' must be between 1 and 58 but is set to '59'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := WithLN(tc.have)(h)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestWithR(t *testing.T) {
	testCases := []struct {
		name string
		have int
		err  string
	}{
		{"ShouldNotErrMin", 1, ""},
		{"ShouldNotErr8", 8, ""},
		{"ShouldErrZero", 0, fmt.Sprintf("scrypt validation error: parameter is invalid: parameter 'block size' must be between 1 and %d but is set to '0'", BlockSizeMax)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := WithR(tc.have)(h)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestWithP(t *testing.T) {
	testCases := []struct {
		name string
		have int
		err  string
	}{
		{"ShouldNotErrMin", 1, ""},
		{"ShouldErrZero", 0, "scrypt validation error: parameter is invalid: parameter 'parallelism' must be between 1 and 1073741823 but is set to '0'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := WithP(tc.have)(h)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestWithK(t *testing.T) {
	testCases := []struct {
		name string
		have int
		err  string
	}{
		{"ShouldNotErrMin", 1, ""},
		{"ShouldNotErr32", 32, ""},
		{"ShouldErrZero", 0, fmt.Sprintf("scrypt validation error: parameter is invalid: parameter 'key length' must be between 1 and %d but is set to '0'", KeyLengthMax)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := WithK(tc.have)(h)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestWithS(t *testing.T) {
	testCases := []struct {
		name string
		have int
		err  string
	}{
		{"ShouldNotErrMin", 8, ""},
		{"ShouldNotErrMax", 1024, ""},
		{"ShouldErrBelowMin", 7, "scrypt validation error: parameter is invalid: parameter 'salt length' must be between 8 and 1024 but is set to '7'"},
		{"ShouldErrAboveMax", 1025, "scrypt validation error: parameter is invalid: parameter 'salt length' must be between 8 and 1024 but is set to '1025'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := WithS(tc.have)(h)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestAliases(t *testing.T) {
	t.Run("ShouldUseWithKeyLength", func(t *testing.T) {
		h := &Hasher{}
		err := WithKeyLength(32)(h)

		assert.NoError(t, err)
		assert.Equal(t, 32, h.k)
	})

	t.Run("ShouldUseWithSaltLength", func(t *testing.T) {
		h := &Hasher{}
		err := WithSaltLength(16)(h)

		assert.NoError(t, err)
		assert.Equal(t, 16, h.bytesSalt)
	})

	t.Run("ShouldUseWithParallelism", func(t *testing.T) {
		h := &Hasher{}
		err := WithParallelism(2)(h)

		assert.NoError(t, err)
		assert.Equal(t, 2, h.p)
	})
}

func TestDigestMatchAdvancedAndString(t *testing.T) {
	hasher, err := NewScrypt(WithLN(4), WithR(1), WithP(1))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	match, err := digest.MatchAdvanced("password")
	assert.NoError(t, err)
	assert.True(t, match)

	assert.Equal(t, digest.Encode(), digest.String())
}

func TestNew(t *testing.T) {
	hasher, err := New()

	assert.NoError(t, err)
	assert.NotNil(t, hasher)
}

func TestNewScrypt(t *testing.T) {
	hasher, err := NewScrypt()

	assert.NoError(t, err)
	assert.NotNil(t, hasher)
}

func TestNewYescrypt(t *testing.T) {
	hasher, err := NewYescrypt()

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
			"ShouldHashScrypt",
			func() (*Hasher, error) { return NewScrypt(WithLN(4), WithR(1), WithP(1)) },
			"password",
			"$scrypt$",
		},
		{
			"ShouldHashYescrypt",
			func() (*Hasher, error) { return NewYescrypt(WithLN(4), WithR(1), WithP(1)) },
			"password",
			"$y$",
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
		{"ShouldErrSaltTooShort", make([]byte, 7), "scrypt hashing error: salt is invalid: salt bytes must have a length of between 8 and 1024 but has a length of 7"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := NewScrypt(WithLN(4), WithR(1), WithP(1))
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
	hasher, err := NewScrypt(WithLN(4), WithR(1), WithP(1))
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
		{"ShouldFailInvalidFormat", "$", "scrypt decode error: provided encoded hash has an invalid format"},
		{"ShouldFailUnknownIdentifier", "$unknown$ln=4,r=8,p=1$salt$key", "scrypt decode error: provided encoded hash has an invalid identifier: identifier 'unknown' is not an encoded scrypt digest"},
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
	hasher, err := NewScrypt(WithLN(4), WithR(1), WithP(1))
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
