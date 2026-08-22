package crypt

import (
	"sync"
	"testing"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeIsSafeForConcurrentUse(t *testing.T) {
	const digest = "$2b$12$3XCpXfcQBjcbXFHTLcbFju0KNQ2ipfeNbcH8b7ZgIkXlbNkYbGDWm"

	var wg sync.WaitGroup

	errs := make([]error, 64)

	for i := range errs {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, errs[i] = Decode(digest)
		}()
	}

	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d", i)
	}
}

func TestCheckPasswordDoesNotPanicOnMalformedDigests(t *testing.T) {
	testCases := []struct {
		name   string
		digest string
	}{
		{"ScryptNegativeLN", "$scrypt$ln=-1,r=8,p=1$c2FsdHNhbHQ$a2V5"},
		{"ScryptNegativeR", "$scrypt$ln=16,r=-8,p=1$c2FsdHNhbHQ$a2V5"},
		{"ScryptNegativeP", "$scrypt$ln=16,r=8,p=-1$c2FsdHNhbHQ$a2V5"},
		{"ScryptOversizedLN", "$scrypt$ln=64,r=8,p=1$c2FsdHNhbHQ$a2V5"},
		{"BcryptOversizedCost", "$2b$99$3XCpXfcQBjcbXFHTLcbFju0KNQ2ipfeNbcH8b7ZgIkXlbNkYbGDWm"},
		{"BcryptNegativeCost", "$2b$-1$3XCpXfcQBjcbXFHTLcbFju0KNQ2ipfeNbcH8b7ZgIkXlbNkYbGDWm"},
		{"PBKDF2NegativeIterations", "$pbkdf2-sha256$-5$c2FsdHNhbHQ$c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbA"},
		{"Argon2ZeroParallelism", "$argon2id$v=19$m=8,t=1,p=0$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				valid, err := CheckPassword("password", tc.digest)

				assert.False(t, valid)
				assert.Error(t, err)
			})
		})
	}
}

func TestDigestScanAcceptsByteSlices(t *testing.T) {
	const encoded = "$2b$12$3XCpXfcQBjcbXFHTLcbFju0KNQ2ipfeNbcH8b7ZgIkXlbNkYbGDWm"

	t.Run("Digest", func(t *testing.T) {
		var digest Digest

		require.NoError(t, digest.Scan([]byte(encoded)))
		assert.Equal(t, encoded, digest.Encode())
	})

	t.Run("NullDigest", func(t *testing.T) {
		var digest NullDigest

		require.NoError(t, digest.Scan([]byte(encoded)))
		assert.Equal(t, encoded, digest.Encode())
	})

	t.Run("NullDigestEmptyBytes", func(t *testing.T) {
		var digest NullDigest

		require.NoError(t, digest.Scan([]byte(nil)))
		assert.Equal(t, "", digest.Encode())
	})
}

func TestDigestZeroValueDoesNotPanic(t *testing.T) {
	var digest Digest

	assert.NotPanics(t, func() {
		assert.Equal(t, "", digest.Encode())
		assert.Equal(t, "", digest.String())
		assert.Nil(t, digest.Key())
		assert.Nil(t, digest.Salt())
		assert.False(t, digest.Match("password"))
		assert.False(t, digest.MatchBytes([]byte("password")))
	})

	assert.NotPanics(t, func() {
		match, err := digest.MatchAdvanced("password")

		assert.False(t, match)
		assert.Error(t, err)
	})

	assert.NotPanics(t, func() {
		match, err := digest.MatchBytesAdvanced([]byte("password"))

		assert.False(t, match)
		assert.Error(t, err)
	})
}

func TestDecoderPrefixMatchingIsDeterministic(t *testing.T) {
	decoder := NewDecoder()

	require.NoError(t, decoder.RegisterDecodeFunc("short", newStubDecodeFunc("short")))
	require.NoError(t, decoder.RegisterDecodeFunc("long", newStubDecodeFunc("long")))

	require.NoError(t, decoder.RegisterDecodePrefix("{X}", "short"))
	require.NoError(t, decoder.RegisterDecodePrefix("{X}{Y}", "long"))

	for i := 0; i < 32; i++ {
		digest, err := decoder.Decode("{X}{Y}value")

		require.NoError(t, err)
		assert.Equal(t, "long", digest.Encode())
	}
}

type stubDigest struct {
	name string
}

func (d *stubDigest) Encode() string                          { return d.name }
func (d *stubDigest) String() string                          { return d.name }
func (d *stubDigest) Key() []byte                             { return nil }
func (d *stubDigest) Salt() []byte                            { return nil }
func (d *stubDigest) Match(string) bool                       { return false }
func (d *stubDigest) MatchBytes([]byte) bool                  { return false }
func (d *stubDigest) MatchAdvanced(string) (bool, error)      { return false, nil }
func (d *stubDigest) MatchBytesAdvanced([]byte) (bool, error) { return false, nil }

func newStubDecodeFunc(name string) algorithm.DecodeFunc {
	return func(encodedDigest string) (algorithm.Digest, error) {
		return &stubDigest{name: name}, nil
	}
}
