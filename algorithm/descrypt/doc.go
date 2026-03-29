// Package descrypt provides the traditional Unix DES-based crypt(3) password hashing algorithm.
//
// This is a legacy algorithm retained only for verifying existing password databases.
// It should NOT be used for new password hashing — the 56-bit key space and 8-character
// password limit make it trivially brute-forceable on modern hardware.
package descrypt
