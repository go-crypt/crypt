package descrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	hasher, err := New()

	assert.NoError(t, err)
	assert.NotNil(t, hasher)
}

func TestHashAndDecode(t *testing.T) {
	hasher, err := New()
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	encoded := digest.Encode()
	assert.Len(t, encoded, DigestLength)

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
		{"ShouldNotErrValidSalt", []byte("ab"), ""},
		{"ShouldErrSaltTooShort", []byte("a"), "descrypt hashing error: salt is invalid: salt bytes must have a length of 2 but has a length of 1"},
		{"ShouldErrSaltTooLong", []byte("abc"), "descrypt hashing error: salt is invalid: salt bytes must have a length of 2 but has a length of 3"},
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

func TestHashWithSaltKnownVector(t *testing.T) {
	hasher, err := New()
	require.NoError(t, err)

	digest, err := hasher.HashWithSalt("password", []byte("ab"))
	require.NoError(t, err)

	assert.Equal(t, "abJnggxhB/yWI", digest.Encode())
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
			"ShouldDecodeValid",
			"abJnggxhB/yWI",
			"",
		},
		{
			"ShouldFailTooShort",
			"abJnggxhB/yW",
			"descrypt decode error: provided encoded hash has an invalid format: digest must be exactly 13 characters but has 12",
		},
		{
			"ShouldFailTooLong",
			"abJnggxhB/yWIx",
			"descrypt decode error: provided encoded hash has an invalid format: digest must be exactly 13 characters but has 14",
		},
		{
			"ShouldFailInvalidChar",
			"abJnggxhB/yW!",
			"descrypt decode error: provided encoded hash has an invalid format: invalid character at position 12",
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

func TestDigestMatch(t *testing.T) {
	testCases := []struct {
		name     string
		encoded  string
		password string
		expected bool
	}{
		{"ShouldMatchPassword", "abJnggxhB/yWI", "password", true},
		{"ShouldNotMatchWrong", "abJnggxhB/yWI", "wrong", false},
		{"ShouldMatchTest", "zzIUSbhjhhESA", "test", true},
		{"ShouldMatchEmpty", "aaQSqAReePlq6", "", true},
		{"ShouldTruncateAt8Chars", "Ax9nM/wNBnYCo", "12345678", true},
		{"ShouldTruncateAt8CharsLonger", "Ax9nM/wNBnYCo", "123456789", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.encoded)
			require.NoError(t, err)

			assert.Equal(t, tc.expected, digest.Match(tc.password))
		})
	}
}

func TestDigestMatchAdvancedAndString(t *testing.T) {
	digest, err := Decode("abJnggxhB/yWI")
	require.NoError(t, err)

	match, err := digest.MatchAdvanced("password")
	assert.NoError(t, err)
	assert.True(t, match)

	assert.Equal(t, "abJnggxhB/yWI", digest.Encode())
	assert.Equal(t, "abJnggxhB/yWI", digest.String())
}
