package sha1crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithIterations(t *testing.T) {
	testCases := []struct {
		name string
		have uint32
		err  string
	}{
		{"ShouldNotErrZero", 0, ""},
		{"ShouldNotErrDefault", 480000, ""},
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
		{"ShouldNotErrMin", 0, ""},
		{"ShouldNotErrMax", 64, ""},
		{"ShouldErrBelowMin", -1, "sha1crypt validation error: parameter is invalid: parameter 'salt length' must be between 0 and 64 but is set to '-1'"},
		{"ShouldErrAboveMax", 65, "sha1crypt validation error: parameter is invalid: parameter 'salt length' must be between 0 and 64 but is set to '65'"},
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
	err := WithRounds(1000)(h)

	assert.NoError(t, err)
	assert.Equal(t, uint32(1000), h.iterations)
}

func TestDigestMatchAdvanced(t *testing.T) {
	hasher, err := New(WithIterations(1000))
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
		{"ShouldNotErrWithIterations", []Opt{WithIterations(1000)}, ""},
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
	hasher, err := New(WithIterations(1000))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	encoded := digest.Encode()
	assert.Contains(t, encoded, "$sha1$")

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
		{"ShouldNotErrValidSalt", []byte("abcdefgh"), ""},
		{"ShouldErrSaltTooLong", make([]byte, 65), "sha1crypt hashing error: salt is invalid: salt bytes must have a length of between 0 and 64 but has a length of 65"},
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
		{"ShouldFailInvalidFormat", "$", "sha1crypt decode error: provided encoded hash has an invalid format"},
		{"ShouldFailWrongIdentifier", "$md5$480000$salt$key", "sha1crypt decode error: provided encoded hash has an invalid identifier: identifier 'md5' is not an encoded sha1crypt digest"},
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

func TestDigestEncode(t *testing.T) {
	hasher, err := New(WithIterations(1000))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	encoded := digest.Encode()
	assert.NotEmpty(t, encoded)
	assert.Equal(t, encoded, digest.String())
}
