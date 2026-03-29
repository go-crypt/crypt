package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplit(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		n        int
		expected []string
	}{
		{
			"ShouldSplitEncodedDigest",
			"$argon2id$v=19$m=65536,t=3,p=4$salt$key",
			3,
			[]string{"", "argon2id", "v=19$m=65536,t=3,p=4$salt$key"},
		},
		{
			"ShouldSplitEncodedDigestUnlimited",
			"$5$salt$key",
			-1,
			[]string{"", "5", "salt", "key"},
		},
		{
			"ShouldSplitEmptyString",
			"",
			3,
			[]string{""},
		},
		{
			"ShouldSplitNoDelimiters",
			"nope",
			3,
			[]string{"nope"},
		},
		{
			"ShouldSplitSingleDelimiter",
			"$abc",
			3,
			[]string{"", "abc"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := Split(tc.have, tc.n)

			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestParameterInt(t *testing.T) {
	testCases := []struct {
		name     string
		have     Parameter
		expected int
		err      string
	}{
		{
			"ShouldConvertValidInt",
			Parameter{Key: "t", Value: "3"},
			3,
			"",
		},
		{
			"ShouldConvertZero",
			Parameter{Key: "t", Value: "0"},
			0,
			"",
		},
		{
			"ShouldFailInvalidInt",
			Parameter{Key: "t", Value: "abc"},
			0,
			`strconv.Atoi: parsing "abc": invalid syntax`,
		},
		{
			"ShouldFailEmptyValue",
			Parameter{Key: "t", Value: ""},
			0,
			`strconv.Atoi: parsing "": invalid syntax`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := tc.have.Int()

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDecodeParameterStr(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected []Parameter
		err      string
	}{
		{
			"ShouldDecodeMultipleParameters",
			"m=65536,t=3,p=4",
			[]Parameter{
				{Key: "m", Value: "65536"},
				{Key: "t", Value: "3"},
				{Key: "p", Value: "4"},
			},
			"",
		},
		{
			"ShouldDecodeSingleParameter",
			"t=3",
			[]Parameter{
				{Key: "t", Value: "3"},
			},
			"",
		},
		{
			"ShouldFailEmptyString",
			"",
			nil,
			"empty strings can't be decoded to parameters",
		},
		{
			"ShouldFailMissingSeparator",
			"abc",
			nil,
			"parameter pair 'abc' is not properly encoded: does not contain kv separator '='",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := DecodeParameterStr(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDecodeParameterStrAdvanced(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		sepItem  string
		sepKV    string
		expected []Parameter
		err      string
	}{
		{
			"ShouldDecodeWithCustomSeparators",
			"a:1;b:2",
			";",
			":",
			[]Parameter{
				{Key: "a", Value: "1"},
				{Key: "b", Value: "2"},
			},
			"",
		},
		{
			"ShouldFailEmptyInput",
			"",
			",",
			"=",
			nil,
			"empty strings can't be decoded to parameters",
		},
		{
			"ShouldFailInvalidKVPair",
			"a:1;b2",
			";",
			":",
			nil,
			"parameter pair 'b2' is not properly encoded: does not contain kv separator ':'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := DecodeParameterStrAdvanced(tc.input, tc.sepItem, tc.sepKV)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}
