package validate

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRange(t *testing.T) {
	errSentinel := errors.New("sentinel")

	testCases := []struct {
		name     string
		value    int
		expected string
	}{
		{"ShouldPassAtMinimum", 1, ""},
		{"ShouldPassWithinRange", 5, ""},
		{"ShouldPassAtMaximum", 10, ""},
		{"ShouldFailBelowMinimum", 0, "sentinel: parameter 'p' must be between 1 and 10 but is set to '0'"},
		{"ShouldFailAboveMaximum", 11, "sentinel: parameter 'p' must be between 1 and 10 but is set to '11'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := Range(errSentinel, "p", tc.value, 1, 10)

			if tc.expected == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expected)
				assert.ErrorIs(t, err, errSentinel)
			}
		})
	}
}

func TestRangeUint32(t *testing.T) {
	assert.NoError(t, Range(errors.New("sentinel"), "m", uint32(8), 8, 4294967295))
	assert.EqualError(t, Range(errors.New("sentinel"), "m", uint32(7), 8, 4294967295), "sentinel: parameter 'm' must be between 8 and 4294967295 but is set to '7'")
}
