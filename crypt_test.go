package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-crypt/crypt/algorithm"
)

func TestNormalize(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected string
	}{
		{
			"ShouldStripCRYPTPrefix",
			"{CRYPT}$6$salt$key",
			"$6$salt$key",
		},
		{
			"ShouldStripARGON2Prefix",
			"{ARGON2}$argon2id$v=19$m=65536,t=3,p=4$salt$key",
			"$argon2id$v=19$m=65536,t=3,p=4$salt$key",
		},
		{
			"ShouldRewritePBKDF2Prefix",
			"{PBKDF2-SHA256}310000$salt$key",
			"$pbkdf2-sha256$310000$salt$key",
		},
		{
			"ShouldRewritePBKDF2PrefixWithoutSHAVariant",
			"{PBKDF2}120000$salt$key",
			"$pbkdf2$120000$salt$key",
		},
		{
			"ShouldNotModifyNormalDigest",
			"$6$salt$key",
			"$6$salt$key",
		},
		{
			"ShouldHandleEmptyString",
			"",
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, Normalize(tc.have))
		})
	}
}

func TestNewDecoder(t *testing.T) {
	d := NewDecoder()
	assert.NotNil(t, d)
}

func TestNewDefaultDecoder(t *testing.T) {
	d, err := NewDefaultDecoder()

	require.NoError(t, err)
	assert.NotNil(t, d)

	digest, err := d.Decode(encodedArgon2id)
	require.NoError(t, err)
	assert.NotNil(t, digest)
}

func TestNewDecoderAll(t *testing.T) {
	d, err := NewDecoderAll()

	require.NoError(t, err)
	assert.NotNil(t, d)

	digest, err := d.Decode("$plaintext$password")
	require.NoError(t, err)
	assert.NotNil(t, digest)
	assert.True(t, digest.Match("password"))
}

func TestDecoderRegisterDecodeFunc(t *testing.T) {
	testCases := []struct {
		name       string
		setup      func(d *Decoder)
		identifier string
		err        string
	}{
		{
			"ShouldRegisterNew",
			nil,
			"test",
			"",
		},
		{
			"ShouldFailDuplicate",
			func(d *Decoder) {
				_ = d.RegisterDecodeFunc("test", func(encodedDigest string) (algorithm.Digest, error) {
					return nil, nil
				})
			},
			"test",
			"decoder already registered for identifier 'test'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDecoder()

			if tc.setup != nil {
				tc.setup(d)
			}

			err := d.RegisterDecodeFunc(tc.identifier, func(encodedDigest string) (algorithm.Digest, error) {
				return nil, nil
			})

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDecoderRegisterDecodePrefix(t *testing.T) {
	testCases := []struct {
		name       string
		setup      func(d *Decoder)
		prefix     string
		identifier string
		err        string
	}{
		{
			"ShouldFailNoDecoders",
			func(d *Decoder) {
				d.decoders = nil
			},
			"{TEST}",
			"test",
			"no decoders are registered",
		},
		{
			"ShouldFailUnregisteredIdentifier",
			nil,
			"{TEST}",
			"missing",
			"decoder isn't registered for dentifier 'missing'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDecoder()

			if tc.setup != nil {
				tc.setup(d)
			}

			err := d.RegisterDecodePrefix(tc.prefix, tc.identifier)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDecoderDecode(t *testing.T) {
	testCases := []struct {
		name string
		have string
		err  string
	}{
		{
			"ShouldDecodeValidArgon2id",
			encodedArgon2id,
			"",
		},
		{
			"ShouldFailInvalidIdentifier",
			"$unknown$abc",
			"provided encoded hash has an invalid identifier: the identifier 'unknown' is unknown to the decoder",
		},
		{
			"ShouldFailNoDelimiter",
			"nope",
			"provided encoded hash has an invalid format: the digest doesn't begin with the delimiter '$' and is not one of the other understood formats",
		},
		{
			"ShouldFailTooFewParts",
			"$",
			"provided encoded hash has an invalid format: the digest doesn't have the minimum number of parts for it to be considered an encoded digest",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDefaultDecoder()
			require.NoError(t, err)

			digest, err := d.Decode(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.NotNil(t, digest)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	testCases := []struct {
		name string
		have string
		err  string
	}{
		{
			"ShouldDecodeValid",
			encodedArgon2id,
			"",
		},
		{
			"ShouldFailInvalid",
			"$unknown$abc",
			"provided encoded hash has an invalid identifier: the identifier 'unknown' is unknown to the global decoder",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := Decode(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.NotNil(t, digest)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestCheckPassword(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		digest   string
		expected bool
		err      string
	}{
		{
			"ShouldMatchCorrectPassword",
			password,
			encodedArgon2id,
			true,
			"",
		},
		{
			"ShouldNotMatchWrongPassword",
			wrongPassword,
			encodedArgon2id,
			false,
			"",
		},
		{
			"ShouldFailInvalidDigest",
			password,
			"invalid",
			false,
			"provided encoded hash has an invalid format: the digest doesn't begin with the delimiter '$' and is not one of the other understood formats",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := CheckPassword(tc.password, tc.digest)

			assert.Equal(t, tc.expected, valid)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestCheckPasswordWithPlainText(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		digest   string
		expected bool
		err      string
	}{
		{
			"ShouldMatchPlainText",
			password,
			"$plaintext$password",
			true,
			"",
		},
		{
			"ShouldNotMatchPlainTextWrong",
			wrongPassword,
			"$plaintext$password",
			false,
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := CheckPasswordWithPlainText(tc.password, tc.digest)

			assert.Equal(t, tc.expected, valid)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestNewDigest(t *testing.T) {
	testCases := []struct {
		name string
		have algorithm.Digest
		err  string
	}{
		{
			"ShouldFailNil",
			nil,
			"can't create crypt.Digest from nil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := NewDigest(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.NotNil(t, digest)
			} else {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, digest)
			}
		})
	}

	t.Run("ShouldCreateFromValidDigest", func(t *testing.T) {
		algDigest, err := Decode(encodedArgon2id)
		require.NoError(t, err)

		digest, err := NewDigest(algDigest)
		require.NoError(t, err)
		assert.NotNil(t, digest)
		assert.True(t, digest.Match(password))
	})
}

func TestNewDigestDecode(t *testing.T) {
	testCases := []struct {
		name string
		have string
		err  string
	}{
		{
			"ShouldDecodeValid",
			encodedArgon2id,
			"",
		},
		{
			"ShouldFailEmpty",
			"",
			"can't create crypt.Digest from empty string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := NewDigestDecode(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.NotNil(t, digest)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDigestMethods(t *testing.T) {
	digest, err := NewDigestDecode(encodedArgon2id)
	require.NoError(t, err)

	t.Run("ShouldEncode", func(t *testing.T) {
		assert.NotEmpty(t, digest.Encode())
	})

	t.Run("ShouldString", func(t *testing.T) {
		assert.NotEmpty(t, digest.String())
	})

	t.Run("ShouldMatchCorrect", func(t *testing.T) {
		assert.True(t, digest.Match(password))
	})

	t.Run("ShouldMatchBytesCorrect", func(t *testing.T) {
		assert.True(t, digest.MatchBytes([]byte(password)))
	})

	t.Run("ShouldMatchAdvancedCorrect", func(t *testing.T) {
		match, err := digest.MatchAdvanced(password)
		assert.NoError(t, err)
		assert.True(t, match)
	})

	t.Run("ShouldMatchBytesAdvancedCorrect", func(t *testing.T) {
		match, err := digest.MatchBytesAdvanced([]byte(password))
		assert.NoError(t, err)
		assert.True(t, match)
	})

	t.Run("ShouldNotMatchWrong", func(t *testing.T) {
		assert.False(t, digest.Match(wrongPassword))
	})

	t.Run("ShouldReturnValue", func(t *testing.T) {
		value, err := digest.Value()
		assert.NoError(t, err)
		assert.NotEmpty(t, value)
	})
}

func TestDigestScan(t *testing.T) {
	testCases := []struct {
		name string
		have interface{}
		err  string
	}{
		{
			"ShouldFailNil",
			nil,
			"invalid type for crypt.Digest: can't scan nil value into crypt.Digest: use crypt.NullDigest instead",
		},
		{
			"ShouldScanString",
			encodedArgon2id,
			"",
		},
		{
			"ShouldFailInvalidType",
			123,
			"invalid type for crypt.Digest: can't scan int into crypt.Digest",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Digest{}
			err := d.Scan(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDigestMarshalUnmarshalText(t *testing.T) {
	t.Run("ShouldRoundTrip", func(t *testing.T) {
		digest, err := NewDigestDecode(encodedArgon2id)
		require.NoError(t, err)

		data, err := digest.MarshalText()
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		newDigest := &Digest{}
		err = newDigest.UnmarshalText(data)
		require.NoError(t, err)

		assert.True(t, newDigest.Match(password))
	})

	t.Run("ShouldFailUnmarshalEmpty", func(t *testing.T) {
		d := &Digest{}
		err := d.UnmarshalText([]byte{})

		assert.EqualError(t, err, "can't unmarhsal empty data to crypt.Digest")
	})

	t.Run("ShouldMarshalNilDigest", func(t *testing.T) {
		d := &Digest{}
		data, err := d.MarshalText()

		assert.NoError(t, err)
		assert.Equal(t, []byte(""), data)
	})
}

func TestDigestMarshalUnmarshalBinary(t *testing.T) {
	digest, err := NewDigestDecode(encodedArgon2id)
	require.NoError(t, err)

	data, err := digest.MarshalBinary()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	newDigest := &Digest{}
	err = newDigest.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.True(t, newDigest.Match(password))
}

func TestNewNullDigest(t *testing.T) {
	t.Run("ShouldCreateWithNil", func(t *testing.T) {
		d := NewNullDigest(nil)
		assert.NotNil(t, d)
	})

	t.Run("ShouldCreateWithDigest", func(t *testing.T) {
		algDigest, err := Decode(encodedArgon2id)
		require.NoError(t, err)

		d := NewNullDigest(algDigest)
		assert.NotNil(t, d)
		assert.True(t, d.Match(password))
	})
}

func TestNewNullDigestDecode(t *testing.T) {
	testCases := []struct {
		name string
		have string
		err  string
	}{
		{
			"ShouldDecodeValid",
			encodedArgon2id,
			"",
		},
		{
			"ShouldReturnEmptyForEmptyString",
			"",
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := NewNullDigestDecode(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.NotNil(t, digest)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestNullDigestNilMethods(t *testing.T) {
	d := NewNullDigest(nil)

	t.Run("ShouldReturnEmptyEncode", func(t *testing.T) {
		assert.Equal(t, "", d.Encode())
	})

	t.Run("ShouldReturnEmptyString", func(t *testing.T) {
		assert.Equal(t, "", d.String())
	})

	t.Run("ShouldReturnFalseMatch", func(t *testing.T) {
		assert.False(t, d.Match("x"))
	})

	t.Run("ShouldReturnFalseMatchBytes", func(t *testing.T) {
		assert.False(t, d.MatchBytes([]byte("x")))
	})

	t.Run("ShouldReturnFalseMatchAdvanced", func(t *testing.T) {
		match, err := d.MatchAdvanced("x")
		assert.NoError(t, err)
		assert.False(t, match)
	})

	t.Run("ShouldReturnFalseMatchBytesAdvanced", func(t *testing.T) {
		match, err := d.MatchBytesAdvanced([]byte("x"))
		assert.NoError(t, err)
		assert.False(t, match)
	})

	t.Run("ShouldReturnNilValue", func(t *testing.T) {
		value, err := d.Value()
		assert.NoError(t, err)
		assert.Nil(t, value)
	})

	t.Run("ShouldReturnNilMarshalText", func(t *testing.T) {
		data, err := d.MarshalText()
		assert.NoError(t, err)
		assert.Nil(t, data)
	})

	t.Run("ShouldHandleUnmarshalTextEmpty", func(t *testing.T) {
		err := d.UnmarshalText([]byte(""))
		assert.NoError(t, err)
	})
}

func TestNullDigestWithDigest(t *testing.T) {
	algDigest, err := Decode(encodedArgon2id)
	require.NoError(t, err)

	d := NewNullDigest(algDigest)

	t.Run("ShouldEncodeNonEmpty", func(t *testing.T) {
		assert.NotEmpty(t, d.Encode())
	})

	t.Run("ShouldMatchPassword", func(t *testing.T) {
		assert.True(t, d.Match(password))
	})

	t.Run("ShouldReturnNonNilValue", func(t *testing.T) {
		value, err := d.Value()
		assert.NoError(t, err)
		assert.NotNil(t, value)
	})
}

func TestNullDigestScan(t *testing.T) {
	testCases := []struct {
		name string
		have interface{}
		err  string
	}{
		{
			"ShouldScanNil",
			nil,
			"",
		},
		{
			"ShouldScanString",
			encodedArgon2id,
			"",
		},
		{
			"ShouldFailInvalidType",
			123,
			"invalid type for crypt.Digest: can't scan int into crypt.Digest",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := &NullDigest{}
			err := d.Scan(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestNullDigestMarshalUnmarshalText(t *testing.T) {
	algDigest, err := Decode(encodedArgon2id)
	require.NoError(t, err)

	d := NewNullDigest(algDigest)

	data, err := d.MarshalText()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	newD := &NullDigest{}
	err = newD.UnmarshalText(data)
	require.NoError(t, err)

	assert.True(t, newD.Match(password))
}

func TestNullDigestMarshalUnmarshalBinary(t *testing.T) {
	algDigest, err := Decode(encodedArgon2id)
	require.NoError(t, err)

	d := NewNullDigest(algDigest)

	data, err := d.MarshalBinary()
	require.NoError(t, err)

	newD := &NullDigest{}
	err = newD.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.True(t, newD.Match(password))
}

var encodedArgon2id = "$argon2id$v=19$m=65536,t=3,p=4$QmkpoTw3W72fzd7RrWofuw$r0xig+VVj7ynnE2S1jrE5us7dPKv2S2ff6Z6ts4mVuU"
