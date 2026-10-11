package argon2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-crypt/crypt/algorithm"
)

func TestHasherNeedsRehash(t *testing.T) {
	base := []Opt{WithVariant(VariantID), WithT(1), WithM(64), WithP(4), WithK(32), WithS(16)}

	testCases := []struct {
		name     string
		have     []Opt
		expected bool
	}{
		{"ShouldNotNeedRehashSameParameters", nil, false},
		{"ShouldNeedRehashVariant", []Opt{WithVariant(VariantI)}, true},
		{"ShouldNeedRehashIterations", []Opt{WithT(2)}, true},
		{"ShouldNeedRehashMemory", []Opt{WithM(128)}, true},
		{"ShouldNeedRehashParallelism", []Opt{WithP(2)}, true},
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
	hasher, err := New(WithVariant(VariantID), WithT(1), WithM(64), WithP(4), WithK(32), WithS(16))
	require.NoError(t, err)

	defaults, err := New()
	require.NoError(t, err)

	salted, err := hasher.HashWithSalt("password", make([]byte, 8))
	require.NoError(t, err)

	digest := func(m uint32) *Digest {
		return &Digest{variant: VariantID, t: 1, m: m, p: 4, salt: make([]byte, 16), key: make([]byte, 32)}
	}

	rounded, err := New(WithVariant(VariantID), WithT(1), WithM(67), WithP(4), WithK(32), WithS(16))
	require.NoError(t, err)

	assert.True(t, hasher.NeedsRehash(nil))
	assert.True(t, hasher.NeedsRehash((*Digest)(nil)))
	assert.True(t, hasher.NeedsRehash(salted))
	assert.False(t, hasher.NeedsRehash(digest(64)))
	assert.False(t, hasher.NeedsRehash(digest(67)))
	assert.True(t, hasher.NeedsRehash(digest(80)))
	assert.False(t, rounded.NeedsRehash(digest(64)))
	assert.False(t, defaults.NeedsRehash(&Digest{
		variant: VariantID, t: IterationsDefault, m: MemoryDefault, p: ParallelismDefault,
		salt: make([]byte, algorithm.SaltLengthDefault), key: make([]byte, KeyLengthDefault),
	}))
}
