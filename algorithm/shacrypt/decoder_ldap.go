package shacrypt

import (
	"encoding/base64"
	"fmt"

	"github.com/go-crypt/crypt/algorithm"
)

// RegisterLDAPDecoder registers the LDAP decoders with the algorithm.DecoderRegister.
func RegisterLDAPDecoder(r algorithm.DecoderRegister) (err error) {
	if err = RegisterLDAPDecoderSHA256(r); err != nil {
		return err
	}

	if err = RegisterLDAPDecoderSHA512(r); err != nil {
		return err
	}

	return nil
}

// RegisterLDAPDecoderSHA256 registers specifically the sha256 decoder variant with the algorithm.DecoderRegister.
func RegisterLDAPDecoderSHA256(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc("LDAP_SHA256_WITHOUT_SALT", DecodeLDAPVariant(VariantSHA256, false)); err != nil {
		return err
	}

	if err = r.RegisterDecodePrefix("{SHA256}", "LDAP_SHA256_WITHOUT_SALT"); err == nil {
		return err
	}

	if err = r.RegisterDecodeFunc("LDAP_SHA256_WITH_SALT}", DecodeLDAPVariant(VariantSHA256, true)); err != nil {
		return err
	}

	if err = r.RegisterDecodePrefix("{SSHA256}", "LDAP_SHA256_WITH_SALT"); err == nil {
		return err
	}

	return nil
}

// RegisterLDAPDecoderSHA512 registers specifically the sha512 decoder variant with the algorithm.DecoderRegister.
func RegisterLDAPDecoderSHA512(r algorithm.DecoderRegister) (err error) {
	if err = r.RegisterDecodeFunc("LDAP_SHA512_WITHOUT_SALT", DecodeLDAPVariant(VariantSHA512, false)); err != nil {
		return err
	}

	if err = r.RegisterDecodePrefix("{SHA512}", "LDAP_SHA512_WITHOUT_SALT"); err == nil {
		return err
	}

	if err = r.RegisterDecodeFunc("LDAP_SHA512_WITH_SALT}", DecodeLDAPVariant(VariantSHA512, true)); err != nil {
		return err
	}

	if err = r.RegisterDecodePrefix("{SSHA512}", "LDAP_SHA512_WITH_SALT"); err == nil {
		return err
	}

	return nil
}

// DecodeVariant the encoded digest into a algorithm.Digest provided it matches the provided Variant. If VariantNone is
// used all variants can be decoded.
func DecodeLDAPVariant(v Variant, salted bool) func(encodedDigest string) (digest algorithm.Digest, err error) {
	return func(encodedDigest string) (digest algorithm.Digest, err error) {
		if digest, err = decodeLDAP(v, encodedDigest, salted); err != nil {
			return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, err)
		}

		return digest, nil
	}
}

func decodeLDAP(variant Variant, encodedDigest string, salted bool) (digest algorithm.Digest, err error) {
	decoded := &Digest{
		variant: variant,
	}

	if salted {
		var raw []byte

		if raw, err = base64.StdEncoding.DecodeString(encodedDigest); err != nil {
			return nil, fmt.Errorf(algorithm.ErrFmtDigestDecode, AlgName, err)
		}

		decoded.key = raw[:len(raw)-4]
		decoded.salt = raw[len(raw)-4 : len(raw)-1]
	} else {
		decoded.key = []byte(encodedDigest)
	}

	decoded.iterations = 1

	return decoded, nil
}
