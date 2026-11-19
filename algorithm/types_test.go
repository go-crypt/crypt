package algorithm

import (
	"errors"
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

func TestUnwrapDigestAs(t *testing.T) {
	inner := &testDigest{}

	var nilDigest *testDigest

	testCases := []struct {
		name     string
		have     Digest
		expected *testDigest
		ok       bool
	}{
		{"ShouldReturnFalseForNil", nil, nil, false},
		{"ShouldReturnFalseForTypedNil", nilDigest, nil, false},
		{"ShouldReturnFalseForOtherType", &testWrapper{inner: &testWrapper{}}, nil, false},
		{"ShouldReturnDigestWhenNotWrapped", inner, inner, true},
		{"ShouldUnwrapNested", &testWrapper{inner: &testWrapper{inner: inner}}, inner, true},
		{"ShouldReturnFalseWhenWrappingTypedNil", &testWrapper{inner: nilDigest}, nil, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := UnwrapDigestAs[testDigest](tc.have)

			assert.Equal(t, tc.ok, ok)

			if tc.ok {
				assert.Same(t, tc.expected, actual)
			}
		})
	}
}

func TestApplyOptions(t *testing.T) {
	errExpected := errors.New("expected")

	type target struct {
		calls []int
	}

	record := func(n int) Opt[*target] {
		return func(h *target) (err error) {
			h.calls = append(h.calls, n)

			return nil
		}
	}

	fail := func(h *target) (err error) {
		return errExpected
	}

	testCases := []struct {
		name     string
		opts     []Opt[*target]
		expected []int
		err      error
	}{
		{"ShouldApplyNone", nil, nil, nil},
		{"ShouldApplyInOrder", []Opt[*target]{record(1), record(2), record(3)}, []int{1, 2, 3}, nil},
		{"ShouldStopAtFirstError", []Opt[*target]{record(1), fail, record(3)}, []int{1}, errExpected},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &target{}

			err := ApplyOptions(h, tc.opts...)

			assert.ErrorIs(t, err, tc.err)
			assert.Equal(t, tc.expected, h.calls)
		})
	}
}
