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

This algorithm was thought of by the developers of [Passlib](https://passlib.readthedocs.io/en/stable/). It circumvents
the issue in bcrypt where the maximum password length is effectively 72 bytes by passing the password via a HMAC-SHA-256
function which uses the salt bytes as the key.

*__Note:__ Only bcrypt-sha256 version 2 which uses the PHC storage format and passes the password through
a HMAC-SHA-256 function the salt as the key is supported. The bcrypt-sha256 version 1 which uses the
[Modular Crypt Format](https://passlib.readthedocs.io/en/stable/modular_crypt_format.html) and only passes the password
via a SHA-256 sum function not supported at all.*