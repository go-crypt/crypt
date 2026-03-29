package math

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoundDownToNearestMultiple(t *testing.T) {
	testCases := []struct {
		name     string
		value    int
		multiple int
		expected int
	}{
		{
			"ShouldRoundDown10To8",
			10,
			8,
			8,
		},
		{
			"ShouldReturnExactMultiple",
			16,
			8,
			16,
		},
		{
			"ShouldRoundDown7To4",
			7,
			4,
			4,
		},
		{
			"ShouldReturnZero",
			3,
			8,
			0,
		},
		{
			"ShouldHandleZeroValue",
			0,
			5,
			0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RoundDownToNearestMultiple(tc.value, tc.multiple)

			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestUint32RoundDownToNearestMultiple(t *testing.T) {
	testCases := []struct {
		name     string
		value    uint32
		multiple uint32
		expected uint32
	}{
		{
			"ShouldRoundDown10To8",
			10,
			8,
			8,
		},
		{
			"ShouldReturnExactMultiple",
			16,
			8,
			16,
		},
		{
			"ShouldRoundDown7To4",
			7,
			4,
			4,
		},
		{
			"ShouldReturnZero",
			3,
			8,
			0,
		},
		{
			"ShouldHandleZeroValue",
			0,
			5,
			0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := Uint32RoundDownToNearestMultiple(tc.value, tc.multiple)

			assert.Equal(t, tc.expected, actual)
		})
	}
}
