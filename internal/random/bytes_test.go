package random

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBytes(t *testing.T) {
	testCases := []struct {
		name     string
		n        int
		expected int
		err      string
	}{
		{
			"ShouldReturnBytesOfLength16",
			16,
			16,
			"",
		},
		{
			"ShouldReturnBytesOfLength32",
			32,
			32,
			"",
		},
		{
			"ShouldReturnEmptyBytesOfLength0",
			0,
			0,
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := Bytes(tc.n)

			if tc.err == "" {
				require.NoError(t, err)
				assert.Len(t, actual, tc.expected)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestCharSetBytes(t *testing.T) {
	testCases := []struct {
		name     string
		n        int
		charset  string
		validate func(t *testing.T, result []byte)
		err      string
	}{
		{
			"ShouldReturnBytesFromCharSet",
			16,
			"abcdef",
			func(t *testing.T, result []byte) {
				assert.Len(t, result, 16)

				for _, b := range result {
					assert.Contains(t, "abcdef", string(b))
				}
			},
			"",
		},
		{
			"ShouldReturnBytesFromNumericCharSet",
			8,
			"0123456789",
			func(t *testing.T, result []byte) {
				assert.Len(t, result, 8)

				for _, b := range result {
					assert.Contains(t, "0123456789", string(b))
				}
			},
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := CharSetBytes(tc.n, tc.charset)

			if tc.err == "" {
				require.NoError(t, err)

				if tc.validate != nil {
					tc.validate(t, actual)
				}
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}
