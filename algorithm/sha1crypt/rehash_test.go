package sha1crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasherNeedsRehash(t *testing.T) {
	base := []Opt{WithIterations(1000), WithSaltLength(8)}

	testCases := []struct {
		name     string
		have     []Opt
		expected bool
	}{
		{"ShouldNotNeedRehashSameParameters", nil, false},
		{"ShouldNeedRehashIterations", []Opt{WithIterations(2000)}, true},
		{"ShouldNeedRehashSaltLength", []Opt{WithSaltLength(4)}, true},
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
	assert.False(t, defaults.NeedsRehash(&Digest{iterations: IterationsDefault, salt: make([]byte, SaltLengthDefault)}))
}
