package crypt

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/algorithm/argon2"
	"github.com/go-crypt/crypt/algorithm/bcrypt"
	"github.com/go-crypt/crypt/algorithm/md5crypt"
	"github.com/go-crypt/crypt/algorithm/pbkdf2"
	"github.com/go-crypt/crypt/algorithm/plaintext"
	"github.com/go-crypt/crypt/algorithm/scrypt"
	"github.com/go-crypt/crypt/algorithm/sha1crypt"
	"github.com/go-crypt/crypt/algorithm/shacrypt"
	"github.com/go-crypt/crypt/internal/encoding"
)

// NewDecoder returns a new empty *Decoder.
//
// See Also: NewDefaultDecoder and NewDecoderAll.
func NewDecoder() *Decoder {
	return &Decoder{
		decoders: map[string]algorithm.DecodeFunc{},
		prefixes: map[string]string{},
	}
}

// NewDefaultDecoder returns the default decoder recommended for new implementations.
//
// Loaded Decoders: argon2, bcrypt, pbkdf2, scrypt, shacrypt.
//
// CRITICAL STABILITY NOTE: the decoders loaded via this function are not guaranteed to remain the same. It is strongly
// recommended that users implementing this library use this or NewDecodersAll only as an example for building their own
// decoder via NewDecoder instead which returns an empty decoder. It is much safer for security and stability to be
// explicit in harmony with your specific use case. It is the responsibility of the implementer to determine which
// password algorithms are sufficiently safe for their particular use case.
func NewDefaultDecoder() (d *Decoder, err error) {
	d = &Decoder{
		decoders: map[string]algorithm.DecodeFunc{},
		prefixes: map[string]string{},
	}

	if err = decoderProfileDefault(d); err != nil {
		return nil, err
	}

	return d, nil
}

// NewDecoderAll is the same as NewDefaultDecoder but it also adds legacy and/or insecure decoders.
//
// Loaded Decoders (in addition to NewDefaultDecoder): plaintext, md5crypt, sha1crypt.
//
// CRITICAL STABILITY NOTE: the decoders loaded via this function are not guaranteed to remain the same. It is strongly
// recommended that users implementing this library use this or NewDecodersAll only as an example for building their own
// decoder via NewDecoder instead which returns an empty decoder. It is much safer for security and stability to be
// explicit in harmony with your specific use case. It is the responsibility of the implementer to determine which
// password algorithms are sufficiently safe for their particular use case.
func NewDecoderAll() (d *Decoder, err error) {
	d = &Decoder{
		decoders: map[string]algorithm.DecodeFunc{},
		prefixes: map[string]string{},
	}

	if err = decoderProfileDefault(d); err != nil {
		return nil, err
	}

	if err = plaintext.RegisterDecoder(d); err != nil {
		return nil, fmt.Errorf("could not register the plaintext decoder: %w", err)
	}

	if err = md5crypt.RegisterDecoder(d); err != nil {
		return nil, fmt.Errorf("could not register the md5crypt decoder: %w", err)
	}

	if err = sha1crypt.RegisterDecoder(d); err != nil {
		return nil, fmt.Errorf("could not register the sha1crypt decoder: %w", err)
	}

	return d, nil
}

// Decoder is a struct which allows registering algorithm.DecodeFunc's and utilizing the programmatically to decode an
// encoded digest with them.
type Decoder struct {
	decoders map[string]algorithm.DecodeFunc
	prefixes map[string]string
}

// RegisterDecodeFunc registers a new algorithm.DecodeFunc with this Decoder against a specific identifier.
func (d *Decoder) RegisterDecodeFunc(identifier string, decoder algorithm.DecodeFunc) (err error) {
	if d.decoders == nil {
		d.decoders = map[string]algorithm.DecodeFunc{}
	}

	if _, ok := d.decoders[identifier]; ok {
		return fmt.Errorf("decoder already registered for identifier '%s'", identifier)
	}

	d.decoders[identifier] = decoder

	return nil
}

// RegisterDecodePrefix registers a prefix which is matched by strings.HasPrefix.
func (d *Decoder) RegisterDecodePrefix(prefix, identifier string) (err error) {
	if d.decoders == nil {
		return fmt.Errorf("no decoders are registered")
	}

	if d.prefixes == nil {
		d.prefixes = map[string]string{}
	}

	if _, ok := d.decoders[identifier]; !ok {
		return fmt.Errorf("decoder isn't registered for dentifier '%s'", identifier)
	}

	d.prefixes[prefix] = identifier

	return nil
}

// Decode an encoded digest into a algorithm.Digest.
func (d *Decoder) Decode(encodedDigest string) (digest algorithm.Digest, err error) {
	if digest, err = d.decode(encodedDigest); err != nil {
		return nil, err
	}

	return digest, nil
}

func (d *Decoder) decode(encodedDigest string) (digest algorithm.Digest, err error) {
	for prefix, key := range d.prefixes {
		if strings.HasPrefix(encodedDigest, prefix) {
			return d.decoders[key](encodedDigest)
		}
	}

	encodedDigest = Normalize(encodedDigest)

	if len(encodedDigest) == 0 || rune(encodedDigest[0]) != encoding.Delimiter {
		return nil, fmt.Errorf("%w: the digest doesn't begin with the delimiter %s and is not one of the other understood formats", algorithm.ErrEncodedHashInvalidFormat, strconv.QuoteRune(encoding.Delimiter))
	}

	parts := encoding.Split(encodedDigest, 3)

	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: the digest doesn't have the minimum number of parts for it to be considered an encoded digest", algorithm.ErrEncodedHashInvalidFormat)
	}

	if decodeFunc, ok := d.decoders[parts[1]]; ok {
		return decodeFunc(encodedDigest)
	}

	switch d {
	case gdecoder:
		return nil, fmt.Errorf("%w: the identifier '%s' is unknown to the global decoder", algorithm.ErrEncodedHashInvalidIdentifier, parts[1])
	default:
		return nil, fmt.Errorf("%w: the identifier '%s' is unknown to the decoder", algorithm.ErrEncodedHashInvalidIdentifier, parts[1])
	}
}

func decoderProfileDefault(decoder *Decoder) (err error) {
	if err = argon2.RegisterDecoder(decoder); err != nil {
		return fmt.Errorf("could not register the argon2 decoder: %w", err)
	}

	if err = bcrypt.RegisterDecoder(decoder); err != nil {
		return fmt.Errorf("could not register the bcrypt decoder: %w", err)
	}

	if err = pbkdf2.RegisterDecoder(decoder); err != nil {
		return fmt.Errorf("could not register the pbkdf2 decoder: %w", err)
	}

	if err = scrypt.RegisterDecoder(decoder); err != nil {
		return fmt.Errorf("could not register the scrypt decoder: %w", err)
	}

	if err = shacrypt.RegisterDecoder(decoder); err != nil {
		return fmt.Errorf("could not register the shacrypt decoder: %w", err)
	}

	if err = shacrypt.RegisterLDAPDecoder(decoder); err != nil {
		return fmt.Errorf("could not register the shacrypt ldap decoder: %w", err)
	}

	return nil
}
