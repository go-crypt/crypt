package scrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-crypt/crypt/algorithm"
)

func TestHasherNeedsRehash(t *testing.T) {
	base := []Opt{WithVariant(VariantScrypt), WithLN(4), WithR(8), WithP(1), WithK(32), WithS(16)}

	testCases := []struct {
		name     string
		have     []Opt
		expected bool
	}{
		{"ShouldNotNeedRehashSameParameters", nil, false},
		{"ShouldNeedRehashVariant", []Opt{WithVariant(VariantYescrypt)}, true},
		{"ShouldNeedRehashLN", []Opt{WithLN(5)}, true},
		{"ShouldNeedRehashR", []Opt{WithR(4)}, true},
		{"ShouldNeedRehashP", []Opt{WithP(2)}, true},
		{"ShouldNeedRehashKeyLength", []Opt{WithK(16)}, true},
		{"ShouldNeedRehashSaltLength", []Opt{WithS(8)}, true},
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

	yescrypt, err := NewYescrypt(WithLN(4), WithR(8), WithP(1))
	require.NoError(t, err)

	digest, err := yescrypt.Hash("password")
	require.NoError(t, err)

	decoded, err := Decode(digest.Encode())
	require.NoError(t, err)

	assert.True(t, defaults.NeedsRehash(nil))
	assert.True(t, defaults.NeedsRehash((*Digest)(nil)))
	assert.False(t, yescrypt.NeedsRehash(digest))
	assert.False(t, yescrypt.NeedsRehash(decoded))
	assert.False(t, defaults.NeedsRehash(&Digest{
		variant: VariantScrypt, ln: IterationsDefault, r: BlockSizeDefault, p: ParallelismDefault,
		salt: make([]byte, algorithm.SaltLengthDefault), key: make([]byte, algorithm.KeyLengthDefault),
	}))
}
