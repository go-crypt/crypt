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

|                                 Algorithm                                  |               Variants               |
|:--------------------------------------------------------------------------:|:------------------------------------:|
|           [Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)            |      Argon2id, Argon2i, Argon2d      |
|        [SHA2 Crypt](https://www.akkadia.org/drepper/SHA-crypt.txt)         |            SHA256, SHA512            |
|                                   PBKDF2                                   | SHA1, SHA224, SHA256, SHA384, SHA512 |
| [bcrypt](https://www.usenix.org/legacy/event/usenix99/provos/provos_html/) |        bcrypt, bcrypt-sha256         |
|           [scrypt](https://www.rfc-editor.org/rfc/rfc7914.html)            |                scrypt                |

### Plain Text Format

In addition to the crypt functions above we also support a plain text storage format which has a regular plain text
variant and a Base64 format (for storage, not security).

The [PHC string format] we decided to use is as follows:

```
$<id>$<data>
```

Where `id` is either `plaintext` or `base64`, and `data` is either the password string or the
[Base64 (Adapted)](#base64-adapted) encoded string.

### bcrypt-sha256

This algorithm was thought of by the developers of [Passlib]. It circumvents the issue in bcrypt where the maximum
password length is effectively 72 bytes by passing the password via a HMAC-SHA-256 function which uses the salt bytes as
the key.

*__Note:__ Only bcrypt-sha256 version 2 which uses the [PHC string format] and passes the password through
a HMAC-SHA-256 function the salt as the key is supported. The bcrypt-sha256 version 1 which uses the 
[Modular Crypt Format] and only passes the password via a SHA-256 sum function not supported at all.*

[Passlib]: https://passlib.readthedocs.io/en/stable/
[PHC string format]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
[Modular Crypt Format]: https://passlib.readthedocs.io/en/stable/modular_crypt_format.html

## Base64 (Adapted)

Many password storage formats use Base64 with an Adapted charset to store the bytes of the salt or hash key. This uses
the standard Base64 encoding without padding as per [RFC4648 section 4] but replaces the `+` chars with a `.`.

[RFC4648 section 4]: https://datatracker.ietf.org/doc/html/rfc4648#section-4

## Usage

The following examples show how easy it is to interact with the argon2 algorithm. Most other algorithm implementations
are relatively similar.

### Decoding a Password and Validating It

```go
package main

import (
	"fmt"

	"github.com/go-crypt/crypt/encoding"
)

func main() {
	decoder, err := encoding.NewDefaultDecoder()
	if err != nil {
		panic(err)
	}
	
	digest, err := decoder.Decode("$argon2id$v=19$m=2097152,t=1,p=4$BjVeoTI4ntTQc0WkFQdLWg$OAUnkkyx5STI0Ixl+OSpv4JnI6J1TYWKuCuvIbUGHTY")
	if err != nil {
		panic(err)
	}
    
    fmt.Printf("Digest Matches Password 'example': %t\n", digest.Match("example"))
	fmt.Printf("Digest Matches Password 'invalid': %t\n", digest.Match("invalid"))
}
```


### Generating an Encoded Digest from a Password

```go
package main

import (
	"fmt"

	"github.com/go-crypt/crypt/algorithm/argon2"
)

func main() {
	hasher, err := argon2.New(
		argon2.WithProfileRFC9106LowMemory(),
	)
	if err != nil {
		panic(err)
	}

	digest, err := hasher.Hash("example")
	if err != nil {
		panic(err)
	}
    
    fmt.Printf("Encoded Digest With Password 'example': %s\n", digest.Encode())
}
```