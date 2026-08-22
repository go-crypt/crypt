package scrypt

import (
	"testing"
)

func FuzzDecodeAndMatch(f *testing.F) {
	seeds := []string{
		"$scrypt$ln=16,r=8,p=1$YmxhaGJsYWhibGFoYmxhaA$Vt4rHrEcdEJ+A9FBAOtqE21NX2NDaCyR3xr0PJmg+dU",
		"$scrypt$ln=1,r=1,p=1$YmxhaGJsYWhibGFoYmxhaA$Vt4rHrEcdEJ+A9FBAOtqE21NX2NDaCyR3xr0PJmg+dU",
		"$scrypt$ln=-1,r=8,p=1$c2FsdHNhbHQ$a2V5",
		"$scrypt$ln=0,r=8,p=1$c2FsdHNhbHQ$a2V5",
		"$scrypt$ln=58,r=8,p=1$c2FsdHNhbHQ$a2V5",
		"$scrypt$ln=59,r=8,p=1$c2FsdHNhbHQ$a2V5",
		"$scrypt$ln=16,r=-8,p=1$c2FsdHNhbHQ$a2V5",
		"$scrypt$ln=16,r=8,p=-1$c2FsdHNhbHQ$a2V5",
		"$scrypt$ln=16,r=0,p=0$c2FsdHNhbHQ$a2V5",
		"$scrypt$$$",
		"$scrypt$ln=x,r=8,p=1$c2FsdA$a2V5",
		"$y$j9T$MnjNJEQnQ0trkgi3VmJJ.$FvSc2M9Xr4mDaIzsHpMxu3T5AQZoCfCz.3Xn8OU9pj5",
		"$y$$$",
		"",
		"$",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, encodedDigest string) {
		decoded, err := Decode(encodedDigest)

		if err != nil {
			return
		}

		digest, ok := decoded.(*Digest)
		if !ok {
			t.Fatalf("Decode(%q) returned a %T rather than a *Digest", encodedDigest, decoded)
		}

		if digest.ln < IterationsMin || digest.ln > IterationsMax {
			t.Fatalf("Decode(%q) accepted an out of range ln of %d", encodedDigest, digest.ln)
		}

		if digest.r < BlockSizeMin || digest.p < ParallelismMin {
			t.Fatalf("Decode(%q) accepted an out of range r of %d or p of %d", encodedDigest, digest.r, digest.p)
		}

		if digest.ln > 12 || digest.r > 16 || digest.p > 4 {
			return
		}

		_, _ = digest.MatchAdvanced("password")
	})
}
