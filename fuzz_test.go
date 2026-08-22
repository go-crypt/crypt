package crypt

import (
	"testing"
)

func FuzzDecode(f *testing.F) {
	for _, seed := range corpusDecode {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, encodedDigest string) {
		digest, err := Decode(encodedDigest)

		if err != nil {
			if digest != nil {
				t.Fatalf("Decode(%q) returned both a digest and the error %v", encodedDigest, err)
			}

			return
		}

		if digest == nil {
			t.Fatalf("Decode(%q) returned no digest and no error", encodedDigest)
		}

		_, _ = digest.Encode(), digest.String()
		_, _ = digest.Key(), digest.Salt()
	})
}

func FuzzNormalize(f *testing.F) {
	for _, seed := range corpusDecode {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, encodedDigest string) {
		normalized := Normalize(encodedDigest)

		if len(normalized) > len(encodedDigest) {
			t.Fatalf("Normalize(%q) returned the longer value %q", encodedDigest, normalized)
		}
	})
}

func TestCheckPasswordNeverPanicsOverCorpus(t *testing.T) {
	for _, encodedDigest := range corpusDecode {
		t.Run(encodedDigest, func(t *testing.T) {
			var (
				valid bool
				err   error
			)

			if !assertNotPanics(t, func() { valid, err = CheckPassword("password", encodedDigest) }) {
				return
			}

			if valid && err != nil {
				t.Fatalf("CheckPassword reported a match alongside the error %v", err)
			}
		})
	}
}

func assertNotPanics(t *testing.T, f func()) (ok bool) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic: %v", r)

			ok = false
		}
	}()

	f()

	return true
}

var corpusDecode = []string{
	// Well formed digests for each supported identifier.
	"$argon2id$v=19$m=2097152,t=1,p=4$YmxhaGJsYWhibGFoYmxhaA$Vt4rHrEcdEJ+A9FBAOtqE21NX2NDaCyR3xr0PJmg+dU",
	"$argon2i$v=19$m=2097152,t=1,p=4$YmxhaGJsYWhibGFoYmxhaA$Vt4rHrEcdEJ+A9FBAOtqE21NX2NDaCyR3xr0PJmg+dU",
	"$argon2d$v=19$m=2097152,t=1,p=4$YmxhaGJsYWhibGFoYmxhaA$Vt4rHrEcdEJ+A9FBAOtqE21NX2NDaCyR3xr0PJmg+dU",
	"$2b$12$3XCpXfcQBjcbXFHTLcbFju0KNQ2ipfeNbcH8b7ZgIkXlbNkYbGDWm",
	"$2a$12$3XCpXfcQBjcbXFHTLcbFju0KNQ2ipfeNbcH8b7ZgIkXlbNkYbGDWm",
	"$2y$12$3XCpXfcQBjcbXFHTLcbFju0KNQ2ipfeNbcH8b7ZgIkXlbNkYbGDWm",
	"$bcrypt-sha256$v=2,t=2b,r=12$3XCpXfcQBjcbXFHTLcbFju$AXNZ1B7NPTf7XyCqUKcvIUOB5eKKZ4C",
	"$pbkdf2-sha256$100000$YmxhaGJsYWhibGFoYmxhaA$Rlt4rHrEcdEJA9FBAOtqE21NX2NDaCyR3xr0PJmg.dU",
	"$scrypt$ln=16,r=8,p=1$YmxhaGJsYWhibGFoYmxhaA$Vt4rHrEcdEJ+A9FBAOtqE21NX2NDaCyR3xr0PJmg+dU",
	"$5$rounds=1000$saltsalt$keykeykeykeykey",
	"$6$rounds=1000$saltsalt$keykeykeykeykey",
	"$6$saltsalt$keykeykeykeykey",
	"$1$saltsalt$keykeykeykeykey",
	"$md5$saltsalt$$keykeykeykeykey",
	"$md5,rounds=1000$saltsalt$$keykeykeykeykey",
	"$sha1$480000$saltsalt$keykeykeykeykey",
	"$plaintext$password",
	"$base64$cGFzc3dvcmQ",

	// LDAP style prefixes handled by Normalize.
	"{CRYPT}$6$rounds=1000$saltsalt$keykeykeykeykey",
	"{ARGON2}$argon2id$v=19$m=2097152,t=1,p=4$YmxhaGJsYWhibGFoYmxhaA$Vt4rHrEcdEJ+A9FBAOtqE21NX2NDaCyR3xr0PJmg+dU",
	"{PBKDF2-SHA256}100000$YmxhaGJsYWhibGFoYmxhaA$Rlt4rHrEcdEJA9FBAOtqE21NX2NDaCyR3xr0PJmg.dU",

	// Parameters which are outside the range each algorithm can actually use.
	"$scrypt$ln=-1,r=8,p=1$c2FsdHNhbHQ$a2V5",
	"$scrypt$ln=64,r=8,p=1$c2FsdHNhbHQ$a2V5",
	"$scrypt$ln=16,r=-8,p=1$c2FsdHNhbHQ$a2V5",
	"$scrypt$ln=16,r=8,p=-1$c2FsdHNhbHQ$a2V5",
	"$2b$99$3XCpXfcQBjcbXFHTLcbFju0KNQ2ipfeNbcH8b7ZgIkXlbNkYbGDWm",
	"$2b$-1$3XCpXfcQBjcbXFHTLcbFju0KNQ2ipfeNbcH8b7ZgIkXlbNkYbGDWm",
	"$2b$00$3XCpXfcQBjcbXFHTLcbFju0KNQ2ipfeNbcH8b7ZgIkXlbNkYbGDWm",
	"$pbkdf2-sha256$0$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5",
	"$pbkdf2-sha256$-5$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5",
	"$argon2id$v=19$m=8,t=0,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5",
	"$argon2id$v=19$m=8,t=1,p=0$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5",
	"$argon2id$v=19$m=0,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5",
	"$argon2id$v=16$m=8,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5",
	"$6$rounds=0$saltsalt$keykeykey",
	"$6$rounds=4294967295$saltsalt$keykeykey",

	// Structurally malformed input.
	"",
	"$",
	"$$",
	"$$$",
	"$$$$$$$$$$",
	"notadigest",
	"$unknown$identifier$value",
	"$argon2id$",
	"$argon2id$v=19$m=2097152,t=1,p=4$$",
	"$2b$",
	"$2b$12$",
	"$scrypt$$$",
	"$plaintext$",
	"$base64$!!!!not-base64!!!!",
	"$argon2id$v=19$m=2097152,t=1,p=4$!!!$!!!",
	"$6$rounds=notanumber$saltsalt$key",
	"$scrypt$ln=notanumber,r=8,p=1$c2FsdA$a2V5",
	"$argon2id$v=19$m=2097152,t=1,p=4,unknown=1$c2FsdA$a2V5",
	"\x00\x00\x00",
	"$\x00$\x00$\x00",
}
