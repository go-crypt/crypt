package descrypt

/*
#cgo CFLAGS: -D_XOPEN_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import "unsafe"

// SaltCharSet is the 64-character alphabet used by DES crypt.
const SaltCharSet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Key derives a traditional Unix DES crypt(3) hash from a password and 2-byte salt.
// Returns the 11-byte encoded hash (not including the 2-char salt prefix).
func Key(password, salt []byte) []byte {
	cPassword := C.CString(string(password))
	defer C.free(unsafe.Pointer(cPassword))

	cSalt := C.CString(string(salt[:2]))
	defer C.free(unsafe.Pointer(cSalt))

	result := C.crypt(cPassword, cSalt)

	goResult := C.GoString(result)

	if len(goResult) < 13 {
		return nil
	}

	return []byte(goResult[2:])
}
