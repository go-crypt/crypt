package plaintext

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasherNeedsRehash(t *testing.T) {
	testCases := []struct {
		name     string
		hasher   []Opt
		digest   []Opt
		expected bool
	}{
		{"ShouldNotNeedRehashSameVariant", []Opt{WithVariant(VariantBase64)}, []Opt{WithVariant(VariantBase64)}, false},
		{"ShouldNotNeedRehashDefaults", nil, []Opt{WithVariant(VariantPlainText)}, false},
		{"ShouldNeedRehashVariant", []Opt{WithVariant(VariantPlainText)}, []Opt{WithVariant(VariantBase64)}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := New(tc.hasher...)
			require.NoError(t, err)

			other, err := New(tc.digest...)
			require.NoError(t, err)

			digest, err := other.Hash("password")
			require.NoError(t, err)

			assert.Equal(t, tc.expected, hasher.NeedsRehash(digest))

			decoded, err := Decode(digest.Encode())
			require.NoError(t, err)

			assert.Equal(t, tc.expected, hasher.NeedsRehash(decoded))
		})
	}

	hasher, err := New()
	require.NoError(t, err)

	assert.True(t, hasher.NeedsRehash(nil))
	assert.True(t, hasher.NeedsRehash((*Digest)(nil)))
}
