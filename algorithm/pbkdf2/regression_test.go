package pbkdf2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVariantConstructorsDeriveKeyLengthFromTheirVariant(t *testing.T) {
	testCases := []struct {
		name    string
		new     func(opts ...Opt) (*Hasher, error)
		variant Variant
	}{
		{"SHA1", NewSHA1, VariantSHA1},
		{"SHA224", NewSHA224, VariantSHA224},
		{"SHA256", NewSHA256, VariantSHA256},
		{"SHA384", NewSHA384, VariantSHA384},
		{"SHA512", NewSHA512, VariantSHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := tc.new(WithIterations(IterationsMin))
			require.NoError(t, err)

			assert.NoError(t, hasher.Validate(), "a hasher returned by the constructor must validate")

			digest, err := hasher.Hash("password")
			require.NoError(t, err)

			assert.Equal(t, tc.variant.HashFunc()().Size(), len(digest.Key()))
			assert.True(t, digest.Match("password"))
		})
	}
}

func TestVariantConstructorsAcceptAKeyLengthOverride(t *testing.T) {
	hasher, err := NewSHA512(WithIterations(IterationsMin), WithKeyLength(80))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	assert.Equal(t, 80, len(digest.Key()))
}

func TestDecodeRejectsUnusableIterations(t *testing.T) {
	testCases := []struct {
		name   string
		digest string
	}{
		{"Zero", "$pbkdf2-sha256$0$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5"},
		{"Negative", "$pbkdf2-sha256$-5$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.digest)

			assert.Nil(t, digest)
			assert.Error(t, err)
		})
	}
}

func TestDecodeAcceptsLegacyIterationCounts(t *testing.T) {
	const encoded = "$pbkdf2-sha256$1000$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5"

	digest, err := Decode(encoded)

	require.NoError(t, err)
	assert.Equal(t, encoded, digest.Encode())
}
