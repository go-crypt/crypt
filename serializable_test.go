package crypt

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSerializableDigest_MarshalJSON(t *testing.T) {
	example, err := Decode("$pbkdf2-sha512$120000$QT7SxFWhHO9s38ofFOKXuQ$XMNoMdUMPFM2UjAeNqGcDZh9e1TPXP8Y5n2JPok.eVk")
	require.NoError(t, err)

	testCases := []struct {
		name     string
		have     any
		expected string
		err      string
	}{
		{
			"ShouldEncodeNull",
			&TestSerializable{},
			`{"value":null}`,
			"",
		},
		{
			"ShouldEncodeNullElem",
			&TestSerializable{Value: &SerializableDigest{}},
			`{"value":null}`,
			"",
		},
		{
			"ShouldEncodeNullOmit",
			&TestSerializableOmitEmpty{},
			`{}`,
			"",
		},
		{
			"ShouldEncodeNullElemOmit",
			&TestSerializableOmitEmpty{Value: &SerializableDigest{}},
			`{"value":null}`,
			"",
		},
		{
			"ShouldEncodePBKDF2",
			&TestSerializable{Value: &SerializableDigest{digest: example}},
			`{"value":"$pbkdf2-sha512$120000$QT7SxFWhHO9s38ofFOKXuQ$XMNoMdUMPFM2UjAeNqGcDZh9e1TPXP8Y5n2JPok.eVk"}`,
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := json.Marshal(tc.have)

			if len(tc.err) == 0 {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, string(out))
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestSerializableDigest_UnmarshalJSON(t *testing.T) {
	example, err := Decode("$pbkdf2-sha512$120000$QT7SxFWhHO9s38ofFOKXuQ$XMNoMdUMPFM2UjAeNqGcDZh9e1TPXP8Y5n2JPok.eVk")
	require.NoError(t, err)

	testCases := []struct {
		name     string
		have     string
		expected any
		err      string
	}{
		{
			"ShouldUnmarshalNull",
			`{"value":null}`,
			&TestSerializable{Value: nil},
			"",
		},
		{
			"ShouldEncodeNullElem",
			`{"value":null}`,
			&TestSerializable{Value: nil},
			"",
		},
		{
			"ShouldEncodePBKDF2",
			`{"value":"$pbkdf2-sha512$120000$QT7SxFWhHO9s38ofFOKXuQ$XMNoMdUMPFM2UjAeNqGcDZh9e1TPXP8Y5n2JPok.eVk"}`,
			&TestSerializable{Value: &SerializableDigest{digest: example}},
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := &TestSerializable{}

			err := json.Unmarshal([]byte(tc.have), actual)

			if len(tc.err) == 0 {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

type TestSerializable struct {
	Value *SerializableDigest `json:"value"`
}

type TestSerializableOmitEmpty struct {
	Value *SerializableDigest `json:"value,omitempty"`
}
