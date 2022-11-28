package encoding

import (
	"fmt"
	"strconv"

	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/algorithm/argon2"
	"github.com/go-crypt/crypt/algorithm/bcrypt"
	"github.com/go-crypt/crypt/algorithm/pbkdf2"
	"github.com/go-crypt/crypt/algorithm/plaintext"
	"github.com/go-crypt/crypt/algorithm/scrypt"
	"github.com/go-crypt/crypt/algorithm/sha2crypt"
	"github.com/go-crypt/crypt/internal/encoding"
)

// NewDecoder returns a new empty *Decoder.
//
// See Also: NewDefaultDecoder and NewDecoderAll.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// NewDefaultDecoder returns the default decoder recommended for new implementations.
//
// Loaded Decoders: argon2, bcrypt, pbkdf2, scrypt, sha2crypt.
func NewDefaultDecoder() (d *Decoder, err error) {
	d = &Decoder{}

	if err = decoderProfileDefault(d); err != nil {
		return nil, err
	}

	return d, nil
}

// NewDecoderAll is the same as NewDefaultDecoder but it also adds legacy and/or insecure decoders.
//
// Loaded Decoders (in addition to NewDefaultDecoder): plaintext.
func NewDecoderAll() (d *Decoder, err error) {
	d = &Decoder{}

	if err = decoderProfileDefault(d); err != nil {
		return nil, err
	}

	if err = plaintext.Register(d); err != nil {
		return nil, fmt.Errorf("could not register the plaintext decoder: %w", err)
	}

	return d, nil
}

// Decoder is a struct which allows registering crypt.DecodeFunc's and utilizing the programmatically to decode an
// encoded digest with them.
type Decoder struct {
	decoders map[string]crypt.DecodeFunc
}

// Register a new decoders crypt.DecodeFunc against a specific identifier.
func (d *Decoder) Register(identifier string, decoder crypt.DecodeFunc) (err error) {
	if d.decoders == nil {
		d.decoders = map[string]crypt.DecodeFunc{}
	}

	if _, ok := d.decoders[identifier]; ok {
		return fmt.Errorf("decoder already registered for identifier '%s'", identifier)
	}

	d.decoders[identifier] = decoder

	return nil
}

// Decode an encoded digest into a crypt.Digest.
func (d *Decoder) Decode(encodedDigest string) (digest crypt.Digest, err error) {
	if digest, err = d.decode(encodedDigest); err != nil {
		return nil, fmt.Errorf("decoder error: %w", err)
	}

	return digest, nil
}

func (d *Decoder) decode(encodedDigest string) (digest crypt.Digest, err error) {
	encodedDigest = Normalize(encodedDigest)

	if len(encodedDigest) == 0 || rune(encodedDigest[0]) != encoding.Delimiter {
		return nil, fmt.Errorf("%w: the hash doesn't begin with the delimiter %s and is not one of the other understood formats", crypt.ErrEncodedHashInvalidFormat, strconv.QuoteRune(encoding.Delimiter))
	}

	parts := encoding.Split(encodedDigest, 3)

	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: the hash doesn't have the minimum number of parts for it to be considered an encoded digest", crypt.ErrEncodedHashInvalidFormat)
	}

	if decodeFunc, ok := d.decoders[parts[1]]; ok {
		return decodeFunc(encodedDigest)
	}

	switch d {
	case gdecoder:
		return nil, fmt.Errorf("%w: the identifier '%s' is unknown to the global decoder", crypt.ErrEncodedHashInvalidIdentifier, parts[1])
	default:
		return nil, fmt.Errorf("%w: the identifier '%s' is unknown to the decoder", crypt.ErrEncodedHashInvalidIdentifier, parts[1])
	}
}

func decoderProfileDefault(decoder *Decoder) (err error) {
	if err = argon2.Register(decoder); err != nil {
		return fmt.Errorf("could not register the argon2 decoder: %w", err)
	}

	if err = bcrypt.Register(decoder); err != nil {
		return fmt.Errorf("could not register the bcrypt decoder: %w", err)
	}

	if err = pbkdf2.Register(decoder); err != nil {
		return fmt.Errorf("could not register the pbkdf2 decoder: %w", err)
	}

	if err = scrypt.Register(decoder); err != nil {
		return fmt.Errorf("could not register the scrypt decoder: %w", err)
	}

	if err = sha2crypt.Register(decoder); err != nil {
		return fmt.Errorf("could not register the sha2crypt decoder: %w", err)
	}

	return nil
}
