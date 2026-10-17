package algorithm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testDigest struct{}

func (d *testDigest) String() string                          { return "" }
func (d *testDigest) Encode() string                          { return "" }
func (d *testDigest) Key() []byte                             { return nil }
func (d *testDigest) Salt() []byte                            { return nil }
func (d *testDigest) Match(string) bool                       { return false }
func (d *testDigest) MatchBytes([]byte) bool                  { return false }
func (d *testDigest) MatchAdvanced(string) (bool, error)      { return false, nil }
func (d *testDigest) MatchBytesAdvanced([]byte) (bool, error) { return false, nil }

type testWrapper struct {
	testDigest

	inner Digest
}

func (d *testWrapper) Unwrap() Digest { return d.inner }

func TestUnwrapDigest(t *testing.T) {
	inner := &testDigest{}

	testCases := []struct {
		name     string
		have     Digest
		expected Digest
	}{
		{"ShouldReturnNilForNil", nil, nil},
		{"ShouldReturnSameDigestWhenNotWrapped", inner, inner},
		{"ShouldUnwrapOnce", &testWrapper{inner: inner}, inner},
		{"ShouldUnwrapNested", &testWrapper{inner: &testWrapper{inner: inner}}, inner},
		{"ShouldReturnNilWhenWrappingNil", &testWrapper{}, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, UnwrapDigest(tc.have))
		})
	}
}
