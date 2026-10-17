package shacrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-crypt/crypt/algorithm"
)

func TestHasherNeedsRehash(t *testing.T) {
	base := []Opt{WithVariant(VariantSHA512), WithIterations(1000), WithSaltLength(16)}

	testCases := []struct {
		name     string
		have     []Opt
		expected bool
	}{
		{"ShouldNotNeedRehashSameParameters", nil, false},
		{"ShouldNeedRehashVariant", []Opt{WithVariant(VariantSHA256)}, true},
		{"ShouldNeedRehashIterations", []Opt{WithIterations(2000)}, true},
		{"ShouldNeedRehashSaltLength", []Opt{WithSaltLength(8)}, true},
	}

	hasher, err := New(base...)
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			other, err := New(append(append([]Opt{}, base...), tc.have...)...)
			require.NoError(t, err)

			digest, err := other.Hash("password")
			require.NoError(t, err)

			assert.Equal(t, tc.expected, hasher.NeedsRehash(digest))

			decoded, err := Decode(digest.Encode())
			require.NoError(t, err)

			assert.Equal(t, tc.expected, hasher.NeedsRehash(decoded))
		})
	}
}

func TestHasherNeedsRehashSpecial(t *testing.T) {
	defaults, err := New()
	require.NoError(t, err)

	assert.True(t, defaults.NeedsRehash(nil))
	assert.True(t, defaults.NeedsRehash((*Digest)(nil)))
	assert.False(t, defaults.NeedsRehash(&Digest{
		variant: VariantSHA512, iterations: VariantSHA512.DefaultIterations(),
		salt: make([]byte, algorithm.SaltLengthDefault),
	}))
}
