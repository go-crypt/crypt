package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/algorithm/argon2"
	"github.com/go-crypt/crypt/algorithm/bcrypt"
	"github.com/go-crypt/crypt/algorithm/md5crypt"
	"github.com/go-crypt/crypt/algorithm/pbkdf2"
	"github.com/go-crypt/crypt/algorithm/plaintext"
	"github.com/go-crypt/crypt/algorithm/scrypt"
	"github.com/go-crypt/crypt/algorithm/sha1crypt"
	"github.com/go-crypt/crypt/algorithm/shacrypt"
)

func TestDigestUnwrap(t *testing.T) {
	inner, err := plaintext.Decode("$plaintext$example")
	require.NoError(t, err)

	digest, err := NewDigest(inner)
	require.NoError(t, err)

	assert.Equal(t, inner, digest.Unwrap())
	assert.Equal(t, inner, algorithm.UnwrapDigest(digest))
	assert.Equal(t, inner, NewNullDigest(inner).Unwrap())
	assert.Nil(t, NewNullDigest(nil).Unwrap())
	assert.Nil(t, algorithm.UnwrapDigest(NewNullDigest(nil)))
	assert.Nil(t, (*Digest)(nil).Unwrap())
	assert.Nil(t, (*NullDigest)(nil).Unwrap())
	assert.Nil(t, algorithm.UnwrapDigest((*Digest)(nil)))
}

func mustHasher[T algorithm.Hash](hasher T, err error) algorithm.Hash {
	if err != nil {
		panic(err)
	}

	return hasher
}

func TestNeedsRehashCrossAlgorithm(t *testing.T) {
	hashers := []struct {
		name   string
		hasher algorithm.Hash
	}{
		{"Argon2", mustHasher(argon2.New(argon2.WithT(1), argon2.WithM(64), argon2.WithP(4)))},
		{"Bcrypt", mustHasher(bcrypt.New(bcrypt.WithIterations(10)))},
		{"MD5Crypt", mustHasher(md5crypt.New())},
		{"PBKDF2", mustHasher(pbkdf2.New(pbkdf2.WithIterations(100000)))},
		{"PlainText", mustHasher(plaintext.New())},
		{"Scrypt", mustHasher(scrypt.New(scrypt.WithLN(4)))},
		{"SHA1Crypt", mustHasher(sha1crypt.New(sha1crypt.WithIterations(1000)))},
		{"SHACrypt", mustHasher(shacrypt.New(shacrypt.WithIterations(1000)))},
	}

	digests := make([]algorithm.Digest, len(hashers))

	for i, h := range hashers {
		var err error

		digests[i], err = h.hasher.Hash("password")
		require.NoError(t, err)
	}

	for i, h := range hashers {
		checker, ok := h.hasher.(algorithm.RehashChecker)
		require.True(t, ok, h.name)

		for j, d := range hashers {
			t.Run(h.name+"With"+d.name, func(t *testing.T) {
				assert.Equal(t, i != j, checker.NeedsRehash(digests[j]))

				wrapped, err := NewDigest(digests[j])
				require.NoError(t, err)

				assert.Equal(t, i != j, checker.NeedsRehash(wrapped))
				assert.Equal(t, i != j, checker.NeedsRehash(NewNullDigest(digests[j])))
			})
		}

		assert.True(t, checker.NeedsRehash(NewNullDigest(nil)), h.name)
		assert.True(t, checker.NeedsRehash((*Digest)(nil)), h.name)
	}
}
