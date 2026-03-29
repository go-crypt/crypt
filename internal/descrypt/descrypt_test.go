package descrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKey(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		salt     string
		expected string
	}{
		{
			"ShouldMatchReferencePassword",
			"password",
			"ab",
			"JnggxhB/yWI",
		},
		{
			"ShouldMatchReferenceTest",
			"test",
			"zz",
			"IUSbhjhhESA",
		},
		{
			"ShouldMatchReferenceEmpty",
			"",
			"aa",
			"QSqAReePlq6",
		},
		{
			"ShouldMatchReference8Chars",
			"12345678",
			"Ax",
			"9nM/wNBnYCo",
		},
		{
			"ShouldTruncateAt8Chars",
			"123456789",
			"Ax",
			"9nM/wNBnYCo",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := Key([]byte(tc.password), []byte(tc.salt))

			assert.Equal(t, tc.expected, string(result))
		})
	}
}
