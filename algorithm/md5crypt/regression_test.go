package md5crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSunVariantWithIterationsRoundTrips(t *testing.T) {
	hasher, err := New(WithVariant(VariantSun), WithIterations(1000))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	encoded := digest.Encode()

	decoded, err := Decode(encoded)
	require.NoError(t, err, "encoded digest %q could not be decoded", encoded)

	assert.Equal(t, encoded, decoded.Encode())
	assert.True(t, decoded.Match("password"))
	assert.False(t, decoded.Match("incorrect"))
}

func TestSunVariantDecodesLegacyIterationsParameter(t *testing.T) {
	hasher, err := New(WithVariant(VariantSun), WithIterations(1000))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	salt, key := string(digest.Salt()), string(digest.Key())

	legacy := "$md5,iterations=1000$" + salt + "$$" + key

	decoded, err := Decode(legacy)
	require.NoError(t, err)

	assert.True(t, decoded.Match("password"))
}

func TestSunVariantEncodesRoundsParameter(t *testing.T) {
	hasher, err := New(WithVariant(VariantSun), WithIterations(1000))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	assert.Contains(t, digest.Encode(), "$md5,rounds=1000$")
}

func TestSunVariantRejectsRoundsThatOverflow(t *testing.T) {
	testCases := []struct {
		name    string
		encoded string
	}{
		{"Rounds", "$md5,rounds=4294967295$c2FsdHNhbHQ$$a2V5a2V5a2V5a2V5a2V5a2"},
		{"Iterations", "$md5,iterations=4294967295$c2FsdHNhbHQ$$a2V5a2V5a2V5a2V5a2V5a2"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.encoded)

			assert.Nil(t, digest)
			assert.Error(t, err)
		})
	}
}

func TestWithIterationsRejectsRoundsThatOverflow(t *testing.T) {
	_, err := New(WithVariant(VariantSun), WithIterations(IterationsMax+1))

	assert.Error(t, err)

	_, err = New(WithVariant(VariantSun), WithIterations(IterationsMax))

	assert.NoError(t, err)
}
