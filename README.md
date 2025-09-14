[![Go Reference](https://pkg.go.dev/badge/github.com/go-crypt/crypt.svg)](https://pkg.go.dev/github.com/go-crypt/crypt)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-crypt/crypt)](https://goreportcard.com/report/github.com/go-crypt/crypt)

# github.com/go-crypt/crypt

Password Hashing / Digest / Crypt library.

## Intent

This library aims to provide a convenient layer over the go password hashing crypto functions.

## Tasks

A list of tasks that need to be accomplished are listed in the  
[General Project](https://github.com/orgs/go-crypt/projects/1).

## Algorithms

Many algorithms are supported and some normalization is used to cover other storage formats. Normalization converts the
unnormalized digest into one of the [Standard](#standard) formats in order to reduce duplication.

### Supported

#### Standard

|                                  Algorithm                                   |               Variants               |                                         Identifiers                                         |
|:----------------------------------------------------------------------------:|:------------------------------------:|:-------------------------------------------------------------------------------------------:|
|            [Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)             |      Argon2id, Argon2i, Argon2d      |                              `argon2id`, `argon2i`, `argon2d`                               |
|          [SHA-crypt](https://www.akkadia.org/drepper/SHA-crypt.txt)          |            SHA256, SHA512            |                                          `5`, `6`                                           |
|                                    PBKDF2                                    | SHA1, SHA224, SHA256, SHA384, SHA512 | `pbkdf2`, `pbkdf2-sha1`, `pbkdf2-sha224`, `pbkdf2-sha256`, `pbkdf2-sha384`, `pbkdf2-sha512` |
|  [bcrypt](https://www.usenix.org/legacy/event/usenix99/provos/provos_html/)  |        bcrypt, bcrypt-sha256         |                        `2`, `2a`, `2b`, `2x`, `2y`,  `bcrypt-sha256`                        |
|            [scrypt](https://www.rfc-editor.org/rfc/rfc7914.html)             |           scrypt, yescrypt           |                                        `scrypt`, `y`                                        |
|                                   md5crypt                                   |            standard, sun             |                                         `1`, `md5`                                          |
|                                  sha1crypt                                   |               standard               |                                           `sha1`                                            |
|                       [PlainText](#plain-text-format)                        |          plaintext, base64           |                                    `plaintext`, `base64`                                    |

#### LDAP

|                       Algorithm                       |                                               Identifiers                                               |                                 Notes                                 |
|:-----------------------------------------------------:|:-------------------------------------------------------------------------------------------------------:|:---------------------------------------------------------------------:|
| [Argon2](https://www.rfc-editor.org/rfc/rfc9106.html) |                                               `{ARGON2}`                                                |                       Handled by Normalization                        |
|                        PBKDF2                         | `{PBKDF2}`, `{PBKDF2-SHA1}`, `{PBKDF2-SHA224}`, `{PBKDF2-SHA256}`, `{PBKDF2-SHA384}`, `{PBKDF2-SHA512}` |                       Handled by Normalization                        |
|                       sha1crypt                       |                                            `{SHA}`, `{SSHA}`                                            |                       Handled by Normalization                        |
|                       sha2crypt                       |                            `{SHA256}`, `{SSHA256}`, `{SHA512}`, `{SSHA512}`                             |                       Handled by Normalization                        |
|                      Plain Text                       |                                              `{CLEARTEXT}`                                              | Handled by Normalization (See [Plain Text Format](#plain-text-format) |

#### Plain Text Format

In addition to the standard crypt functions we also support a plain text storage format which has a regular plain text
variant and a Base64 format (for storage, not security).

The [PHC string format] we decided to use is as follows:

```
$<id>$<data>
```

Where `id` is either `plaintext` or `base64`, and `data` is either the password string or the
[Base64 (Adapted)](#base64-adapted) encoded string.

#### bcrypt-sha256

This algorithm was thought of by the developers of [Passlib]. It circumvents the issue in bcrypt where the maximum
password length is effectively 72 bytes by passing the password via a HMAC-SHA-256 function which uses the salt bytes as
the key.

*__Note:__ Only bcrypt-sha256 version 2 which uses the [PHC string format] and passes the password through
a HMAC-SHA-256 function the salt as the key is supported. The bcrypt-sha256 version 1 which uses the 
[Modular Crypt Format] and only passes the password via a SHA-256 sum function not supported at all.*

[Passlib]: https://passlib.readthedocs.io/en/stable/
[PHC string format]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
[Modular Crypt Format]: https://passlib.readthedocs.io/en/stable/modular_crypt_format.html

### Possible Future Support

|    Algorithm    |                       Reasoning                       |
|:---------------:|:-----------------------------------------------------:|
| Type 7 (cisco)  | Explicit Backwards Compatibility and Interoperability |
| Type 8 (cisco)  | Explicit Backwards Compatibility and Interoperability |
| Type 9 (cisco)  | Explicit Backwards Compatibility and Interoperability |
| Type 10 (cisco) | Explicit Backwards Compatibility and Interoperability |

Additional support for LDAP specific formats is also very likely, either via normalization and encoding options or via
explicit algorithm variants and/or specific algorithms.

## Base64 (Adapted)

Many password storage formats use Base64 with an Adapted charset to store the bytes of the salt or hash key. This uses
the standard Base64 encoding without padding as per [RFC4648 section 4] but replaces the `+` chars with a `.`.

[RFC4648 section 4]: https://datatracker.ietf.org/doc/html/rfc4648#section-4

## Installation

Use `go get` to add this module to your project with `go get github.com/go-crypt/crypt`.

### Requirements

- go 1.21+

## Usage

The following examples show how easy it is to interact with the argon2 algorithm. Most other algorithm implementations
are relatively similar.

### Functional Options Pattern

The `algorithm.Hasher` implementations use a functional options pattern. This pattern is accessible via the `New`
function in each algorithm package or via a receiver function of the individual `algorithm.Hasher` implementation called
`WithOptions`.

Most algorithm implementations have at least the following functional option signatures:
- `WithVariant(variant Variant) Opt`
- `WithVariantName(identifier string) Opt`
- `WithIterations(iterations int) Opt`

With the exception of `WithVariantName` which takes a string, and `WithVariant` which takes a `Variant` type (which is
technically a int), nearly every functional option takes a single `int`. There are a few functional options which take
a single `uint32` where the maximum value exceeds the maximum value for an untyped int on 32bit architectures.

If the `uint32` methods are an issue for anyone using this module we suggest opening an issue and describing why and we'll
consider adding another functional option which takes an `int`.

### Creating a Decoder

While several convenience functions exist for building password decoders and checking individual passwords it is 
*__STRONGLY RECOMMENDED__* that users implementing this library explicitly create a decoder that fits their particular
use case after sufficiently researching each algorithm and their benefits. At the time of this writing we strongly
recommend the `argon2id` variant of `argon2`.

This can be done via the `crypt.NewDecoder` function as shown below.

```go
package main

import (
    "fmt"

    "github.com/go-crypt/crypt"
    "github.com/go-crypt/crypt/algorithm"
    "github.com/go-crypt/crypt/algorithm/argon2"
)

func main() {
    var (
        decoder *crypt.Decoder
        err    error
        digest algorithm.Digest
    )
    
    if decoder, err = NewDecoderArgon2idOnly(); err != nil {
        panic(err)
    }
    
    if digest, err = decoder.Decode("$argon2id$v=19$m=2097152,t=1,p=4$BjVeoTI4ntTQc0WkFQdLWg$OAUnkkyx5STI0Ixl+OSpv4JnI6J1TYWKuCuvIbUGHTY"); err != nil {
        panic(err)
    }

    fmt.Printf("Digest Matches Password 'example': %t\n", digest.Match("example"))
    fmt.Printf("Digest Matches Password 'invalid': %t\n", digest.Match("invalid"))
}


// NewDecoderArgon2idOnly returns a decoder which can only decode argon2id encoded digests.
func NewDecoderArgon2idOnly() (decoder *crypt.Decoder, err error) {
    decoder = crypt.NewDecoder()

    if err = argon2.RegisterDecoderArgon2id(decoder); err != nil {
        return nil, err
    }
    
    return decoder, nil
}
```
### Decoding a Password and Validating It

This method of checking passwords is recommended if you have a database of hashes which are going to live in memory. The
`crypt.Digest` and `crypt.NullDigest` types provide helpful interface implementations to simplify Marshal/Unmarshal and
database operations.

```go
package main

import (
    "fmt"

    "github.com/go-crypt/crypt"
    "github.com/go-crypt/crypt/algorithm"
)

func main() {
    var (
        decoder *crypt.Decoder
        err error
        digest algorithm.Digest
    )
    
    if decoder, err = crypt.NewDefaultDecoder(); err != nil {
        panic(err)
    }
    
    if digest, err = decoder.Decode("$argon2id$v=19$m=2097152,t=1,p=4$BjVeoTI4ntTQc0WkFQdLWg$OAUnkkyx5STI0Ixl+OSpv4JnI6J1TYWKuCuvIbUGHTY"); err != nil {
        panic(err)
    }
    
    fmt.Printf("Digest Matches Password 'example': %t\n", digest.Match("example"))
    fmt.Printf("Digest Matches Password 'invalid': %t\n", digest.Match("invalid"))
}
```

### Checking a Password Against a Hash

This method of checking passwords is quick and dirty and most useful when users are providing the hash as the input such
as in situations where you are allowing them to check a password themselves via a CLI or otherwise.

```go
package main

import (
    "fmt"

    "github.com/go-crypt/crypt"
)

func main() {
    var (
        valid bool
        err error
    )
    
    if valid, err = crypt.CheckPassword("example","$argon2id$v=19$m=2097152,t=1,p=4$BjVeoTI4ntTQc0WkFQdLWg$OAUnkkyx5STI0Ixl+OSpv4JnI6J1TYWKuCuvIbUGHTY"); err != nil {
        panic(err)
    }
    
    fmt.Printf("Digest Matches Password 'example': %t\n", valid)

    if valid, err = crypt.CheckPassword("invalid","$argon2id$v=19$m=2097152,t=1,p=4$BjVeoTI4ntTQc0WkFQdLWg$OAUnkkyx5STI0Ixl+OSpv4JnI6J1TYWKuCuvIbUGHTY"); err != nil {
        panic(err)
    }

    fmt.Printf("Digest Matches Password 'invalid': %t\n", valid)
}
```

### Generating an Encoded Digest from a Password

```go
package main

import (
    "fmt"

    "github.com/go-crypt/crypt/algorithm"
    "github.com/go-crypt/crypt/algorithm/argon2"
)

func main() {
    var (
        hasher *argon2.Hasher
        err error
        digest algorithm.Digest
    )
    
    if hasher, err = argon2.New(
        argon2.WithProfileRFC9106LowMemory(),
    ); err != nil {
        panic(err)
    }

    if digest, err = hasher.Hash("example"); err != nil {
        panic(err)
    }
    
    fmt.Printf("Encoded Digest With Password 'example': %s\n", digest.Encode())
}
```