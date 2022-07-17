# github.com/go-crypt/crypt

Password Hashing / Digest / Crypt library.

## Intent

This library aims to provide a convenient layer over the go password hashing crypto functions.

## Algorithms

|                                 Algorithm                                  |               Variants               |
|:--------------------------------------------------------------------------:|:------------------------------------:|
|           [Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)            |      Argon2id, Argon2i, Argon2d      |
|        [SHA2 Crypt](https://www.akkadia.org/drepper/SHA-crypt.txt)         |            SHA256, SHA512            |
|                                   PBKDF2                                   | SHA1, SHA224, SHA256, SHA384, SHA512 |
| [bcrypt](https://www.usenix.org/legacy/event/usenix99/provos/provos_html/) |        bcrypt, bcrypt-sha256         |
|           [scrypt](https://www.rfc-editor.org/rfc/rfc7914.html)            |                scrypt                |

In addition to the crypt functions above we also support a plain text storage format which has a regular plain text 
variant and a base64 (for storage, not security) format.

### bcrypt-sha256

This algorithm was thought of by the developers of passlib. It