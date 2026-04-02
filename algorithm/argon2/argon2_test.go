package argon2

import (
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
		{"ShouldReturnVariantID", "argon2id", VariantID},
		{"ShouldReturnVariantI", "argon2i", VariantI},
		{"ShouldReturnVariantD", "argon2d", VariantD},
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
		{"ShouldReturnArgon2id", VariantID, "argon2id"},
		{"ShouldReturnArgon2i", VariantI, "argon2i"},
		{"ShouldReturnArgon2d", VariantD, "argon2d"},
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
		{"ShouldReturnArgon2idPrefix", VariantID, "argon2id"},
		{"ShouldReturnArgon2iPrefix", VariantI, "argon2i"},
		{"ShouldReturnArgon2dPrefix", VariantD, "argon2d"},
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
		{"ShouldReturnIDKeyFunc", VariantID, false},
		{"ShouldReturnIKeyFunc", VariantI, false},
		{"ShouldReturnDKeyFunc", VariantD, false},
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
		{"ShouldNotErrID", VariantID, ""},
		{"ShouldNotErrI", VariantI, ""},
		{"ShouldNotErrD", VariantD, ""},
		{"ShouldNotErrNone", VariantNone, ""},
		{"ShouldErrInvalid", Variant(99), "argon2 validation error: parameter is invalid: variant '99' is invalid"},
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
		{"ShouldNotErrArgon2id", "argon2id", ""},
		{"ShouldNotErrEmpty", "", ""},
		{"ShouldErrInvalid", "invalid", "argon2 validation error: parameter is invalid: variant identifier 'invalid' is invalid"},
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

func TestWithVariantShortcuts(t *testing.T) {
	testCases := []struct {
		name     string
		opt      Opt
		expected Variant
	}{
		{"ShouldSetVariantI", WithVariantI(), VariantI},
		{"ShouldSetVariantID", WithVariantID(), VariantID},
		{"ShouldSetVariantD", WithVariantD(), VariantD},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := tc.opt(h)

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, h.variant)
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
		{"ShouldNotErr4", 4, ""},
		{"ShouldErrZero", 0, "argon2 validation error: parameter is invalid: parameter 'parallelism' must be between 1 and 16777215 but is set to '0'"},
		{"ShouldErrAboveMax", 16777216, "argon2 validation error: parameter is invalid: parameter 'parallelism' must be between 1 and 16777215 but is set to '16777216'"},
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

func TestWithM(t *testing.T) {
	testCases := []struct {
		name string
		have uint32
		err  string
	}{
		{"ShouldNotErrMin", 8, ""},
		{"ShouldNotErr65536", 65536, ""},
		{"ShouldErrBelowMin", 7, "argon2 validation error: parameter is invalid: parameter 'memory' must be between 8 and 4294967295 but is set to '7'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := WithM(tc.have)(h)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestWithT(t *testing.T) {
	testCases := []struct {
		name string
		have int
		err  string
	}{
		{"ShouldNotErrMin", 1, ""},
		{"ShouldNotErr3", 3, ""},
		{"ShouldErrZero", 0, "argon2 validation error: parameter is invalid: parameter 't' must be between 1 and 2147483647 but is set to '0'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := WithT(tc.have)(h)

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
		{"ShouldNotErrMin", 4, ""},
		{"ShouldNotErr32", 32, ""},
		{"ShouldErrBelowMin", 3, "argon2 validation error: parameter is invalid: parameter 'k' must be between 4 and 2147483647 but is set to '3'"},
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
		{"ShouldNotErrMin", 1, ""},
		{"ShouldNotErr16", 16, ""},
		{"ShouldErrZero", 0, "argon2 validation error: parameter is invalid: parameter 's' must be between 1 and 2147483647 but is set to '0'"},
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

func TestProfileHasher(t *testing.T) {
	testCases := []struct {
		name    string
		profile Profile
	}{
		{"ShouldReturnRecommendedHasher", ProfileRFC9106Recommended},
		{"ShouldReturnLowMemoryHasher", ProfileRFC9106LowMemory},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.profile.Hasher()
			assert.NotNil(t, h)
		})
	}
}

func TestNew(t *testing.T) {
	hasher, err := New(WithT(1), WithP(1), WithM(8), WithK(32), WithS(16))

	assert.NoError(t, err)
	assert.NotNil(t, hasher)
}

func TestHashAndDecode(t *testing.T) {
	hasher, err := New(WithT(1), WithP(1), WithM(8), WithK(32), WithS(16))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	encoded := digest.Encode()
	assert.Contains(t, encoded, "$argon2id$")

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
		{"ShouldNotErrValidSalt", make([]byte, 16), ""},
		{"ShouldErrEmptySalt", []byte{}, "argon2 hashing error: salt is invalid: salt bytes must have a length of between 1 and 2147483647 but has a length of 0"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := New(WithT(1), WithP(1), WithM(8), WithK(32), WithS(16))
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
	hasher, err := New(WithT(1), WithP(1), WithM(8), WithK(32), WithS(16))
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		digest := hasher.MustHash("password")
		assert.True(t, digest.Match("password"))
	})
}

func TestCopyCloneMerge(t *testing.T) {
	hasher, err := New(WithT(1), WithP(1), WithM(8), WithK(32), WithS(16))
	require.NoError(t, err)

	t.Run("ShouldClone", func(t *testing.T) {
		cloned := hasher.Clone()
		assert.NotNil(t, cloned)
	})

	t.Run("ShouldCopy", func(t *testing.T) {
		target := &Hasher{}
		hasher.Copy(target)
		assert.Equal(t, hasher.variant, target.variant)
		assert.Equal(t, hasher.t, target.t)
		assert.Equal(t, hasher.p, target.p)
		assert.Equal(t, hasher.m, target.m)
	})

	t.Run("ShouldMerge", func(t *testing.T) {
		target := &Hasher{}
		hasher.Merge(target)
		assert.Equal(t, hasher.variant, target.variant)
		assert.Equal(t, hasher.t, target.t)
		assert.Equal(t, hasher.p, target.p)
		assert.Equal(t, hasher.m, target.m)
	})

	t.Run("ShouldNotOverwriteOnMerge", func(t *testing.T) {
		target := &Hasher{variant: VariantI, t: 5}
		hasher.Merge(target)
		assert.Equal(t, VariantI, target.variant)
		assert.Equal(t, 5, target.t)
	})
}

func TestDecode(t *testing.T) {
	testCases := []struct {
		name string
		have string
		err  string
	}{
		{"ShouldFailInvalidFormat", "$", "argon2 decode error: provided encoded hash has an invalid format"},
		{"ShouldFailUnknownIdentifier", "$unknown$v=19$m=65536,t=3,p=4$salt$key", "argon2 decode error: provided encoded hash has an invalid identifier: identifier 'unknown' is not an encoded argon2 digest"},
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

func TestAliases(t *testing.T) {
	t.Run("ShouldUseWithParallelism", func(t *testing.T) {
		h := &Hasher{}
		err := WithParallelism(4)(h)

		assert.NoError(t, err)
		assert.Equal(t, 4, h.p)
	})

	t.Run("ShouldUseWithMemoryInKiB", func(t *testing.T) {
		h := &Hasher{}
		err := WithMemoryInKiB(65536)(h)

		assert.NoError(t, err)
		assert.Equal(t, uint32(65536), h.m)
	})

	t.Run("ShouldUseWithIterations", func(t *testing.T) {
		h := &Hasher{}
		err := WithIterations(3)(h)

		assert.NoError(t, err)
		assert.Equal(t, 3, h.t)
	})

	t.Run("ShouldUseWithTagLength", func(t *testing.T) {
		h := &Hasher{}
		err := WithTagLength(32)(h)

		assert.NoError(t, err)
		assert.Equal(t, 32, h.k)
	})

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
		assert.Equal(t, 16, h.s)
	})
}

func TestDigestMatchAdvanced(t *testing.T) {
	hasher, err := New(WithT(1), WithP(1), WithM(8), WithK(32), WithS(16))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	match, err := digest.MatchAdvanced("password")
	assert.NoError(t, err)
	assert.True(t, match)

	assert.Equal(t, digest.Encode(), digest.String())
}

func TestDigestKeySalt(t *testing.T) {
	hasher, err := New(WithT(1), WithP(1), WithM(8), WithK(32), WithS(16))
	require.NoError(t, err)

	digest, err := hasher.Hash("password")
	require.NoError(t, err)

	d, ok := digest.(*Digest)
	require.True(t, ok)

	assert.NotEmpty(t, d.Key())
	assert.Len(t, d.Key(), 32)
	assert.NotEmpty(t, d.Salt())
	assert.Len(t, d.Salt(), 16)
}

func TestWithProfileRFC9106(t *testing.T) {
	testCases := []struct {
		name string
		opt  Opt
	}{
		{"ShouldApplyRecommendedProfile", WithProfileRFC9106Recommended()},
		{"ShouldApplyLowMemoryProfile", WithProfileRFC9106LowMemory()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hasher{}
			err := tc.opt(h)

			assert.NoError(t, err)
		})
	}
}
