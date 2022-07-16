package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	for _, source := range testSources {
		t.Run(source.name, func(t *testing.T) {
			for _, algorithm := range source.algorithms {
				t.Run(algorithm.name, func(t *testing.T) {
					for _, password := range algorithm.passwords {
						t.Run(password.password, func(t *testing.T) {
							digest, err := Decode(password.digest)

							assert.NoError(t, err)
							require.NotNil(t, digest)

							assert.True(t, digest.Match(password.password))

							assert.Equal(t, NormalizeEncodedDigest(password.digest), digest.String())
						})
					}
				})
			}
		})
	}
}

type testSource struct {
	name       string
	algorithms []testAlgorithm
}

type testAlgorithm struct {
	name      string
	passwords []testPassword
}

type testPassword struct {
	password string
	digest   string
}

var testSources = []testSource{
	{
		name: "Passlib",
		algorithms: []testAlgorithm{
			{
				name: "sha256",
				passwords: []testPassword{
					{"apple123", "$5$rounds=500000$GVVEl8Y7GaqO440/$mr4l6Y7NrD33RcxG1R6tjIeexFAezrA2fn2lKott/T9"},
					{"another", "$5$rounds=500000$jlA/eTgbB9fPlT7s$7LXojgWxd4lkVrG2r9XeElwjUC8RCtJpSkIZInhGbM0"},
					{"th15isalongandcomplexpassw0rd@", "$5$rounds=500000$V/PNqRQpFZaoVW/e$vXVLANsLuvaGKoYJXIeVRk5aAdqX5f8Xqhwb3l9uO81"},
					{"password123", "$5$rounds=500000$P3q/CTOINm/oMhKP$xlIP1t0FAbrJVqTnKtWxUf3yjNDVU3n/nKkuxKhOgdB"},
					{"p@ssw0rd", "$5$rounds=500000$WFjMpdCQxIkbNl0k$M0qZaZoK8Gwdh8Cw5diHgGfe5pE0iJvxcVG3.CVnQe."},
				},
			},
			{
				name: "bcrypt",
				passwords: []testPassword{
					{"apple123", "$2b$13$Aa6FIFnz3feYbEt4eKaRYeTd9y.RGzvRFzvcc5kCM4AONK3p/uH2q"},
					{"another", "$2b$13$hFLbtif0IKeRlyllUrl24uwG7cjCkgCQRXkejULDNWx.QVx7jtdQu"},
					{"th15isalongandcomplexpassw0rd@", "$2b$13$ISD.gkdn3BGQwww9P7aYk..e.hobOmSiY23UTuPDoIzpdbb9GCfEW"},
					{"password123", "$2b$13$C37D8jQVJjjsyvQTz2H7u.wZHJPrJdQrpcd9hM3HhStn9eKs/jely"},
					{"p@ssw0rd", "$2b$13$ecwPFQ4v9gll5qsvtgnYBOsoZ9KgbAVIFxQKz2mDN9OeSlhwEpMmS"},
				},
			},
			{
				name: "pbkdf2-sha256",
				passwords: []testPassword{
					{"apple123", "$pbkdf2-sha256$29000$/N.bsxZibA3B2NubM6b0Xg$pboBgU5tpMWi2YealJZFFzAviGWgHLp1BFXCCibQO6I"},
					{"another", "$pbkdf2-sha256$29000$bK2VEsL4//8fg5Cydo5R6g$2Uqs7veqTp8RJMnakEeQyWeIAX.3OXGYBpDKkBe36.c"},
					{"th15isalongandcomplexpassw0rd@", "$pbkdf2-sha256$29000$wXiPMaYUYowxZux9z7k3xg$hPei4AaHoBb6W6z0cXFKjY7AVseUF7rOAzB7yzY3psc"},
					{"password123", "$pbkdf2-sha256$29000$C.H8PwfgvNdaa21t7Z3zHg$JJEF8JnmHSl.CO49AczNNIPvzNo.KaQGU3T9S3Ebr4M"},
					{"p@ssw0rd", "$pbkdf2-sha256$29000$vvdeK0WoFYJQynmPEaI0xg$cjTBSXTLo.GcJaqQ5BVq5fJnXO1RLUIGoXcJq.yimRk"},
				},
			},
			{
				name: "pbkdf2-sha512",
				passwords: []testPassword{
					{"apple123", "$pbkdf2-sha512$25000$VSolZMy59z4HgPDeWwuBMA$2Ioxz6Zr1jutEYWnFm3X6eIH4TostlklSy4WVWgCQseZuI3LPnw87xJokXj.M1pvobVk1/8NGwGiIvfJuWm63A"},
					{"another", "$pbkdf2-sha512$25000$sJbyXktJyZlzLuX8H6N0zg$cqWvnmPhdAJgBZzqjhRPrhCFQeRJkkCiSaDou9As79JK.nk3NCzA8Rnu9HFyvJM.ovCXg3hEulE8ivtkfCDCgw"},
					{"th15isalongandcomplexpassw0rd@", "$pbkdf2-sha512$25000$rFXqfW8NgXAOAQDAeO9d6w$gNQRGMFY02tpU8uHHd.zoZamRJnpfKmo4eMQbD3yEZ1A4aoV0/hHgJLR/G0xcp9rjhq6TAUa3ims7b31sAveSw"},
					{"password123", "$pbkdf2-sha512$25000$O4fQOmfMuVeqVSqlVMp5Dw$VbePsvwwugYwORElCLcPwr5qlN7tKquf4V7GnoioVJ1Sc/f8Q3RmHZUJ351jiIOHpQ/oLxB16ptjJdrJ9BLxdQ"},
					{"p@ssw0rd", "$pbkdf2-sha512$25000$WOudk1IKQUjJGUOIEaK0lg$gwHiLsQS/G/5TbuulDR2xgF4h/e6unkgrAh.bvAQwl/4LnYjmQ0CW.I7JvqR.h5udllNxbalPUsNJXrPHv.a5w"},
				},
			},
			{
				name: "sha512",
				passwords: []testPassword{
					{"apple123", "$6$rounds=500000$B5uBplhxG6q6SCwr$S3SMNxZAvGeig/EIlE8D.0QfwFa5I2Vllb56tCUVb/HGhyeJ0eQPQvmUW7gTWI7qVlLt6VfJZZZkyfcBkLiqc0"},
					{"another", "$6$rounds=500000$xnYMzhQahYkhoSRE$eL3BetlNbdaDQnVBZY/VPncSBjBr7d3se8nn6eFb7T9PooeAbfcfIPYlfhna8kxgDV1XRjJs3adg8OIeyy6.Y/"},
					{"th15isalongandcomplexpassw0rd@", "$6$rounds=500000$vIr2P3vvZDiDolE.$jRI/5j9sCkt3HXi25y3cS4NQznZuudmOt7sj76tTCMiBlNE3CZgpnrGQnjBC0nMeo6xmZXHbmteHpY/V3eADb0"},
					{"password123", "$6$rounds=500000$Gra7/SdvVelxdbPg$ZPW3y4ohcM6PXVHuMH4SRRpqAdSg6oSzkRZ0kN3MVmhLnZmywr0Hquvi4x6KGX0bJiS0WBzkP7Io7LwBD3BpI1"},
					{"p@ssw0rd", "$6$rounds=500000$x.Vg1kiTQ8G2CTLu$aMK0SuBpPDOAX2FDBzNJRuDrJtBdl3rKxILRO8dgT.qU.Hkl/aZXRS7idSceLuy/x.RTooXgGk6SsoGuDUhVf0"},
				},
			},
			{
				name: "scrypt",
				passwords: []testPassword{
					{"apple123", "$scrypt$ln=15,r=8,p=1$m7M2BqBUytk75zznfK91jg$F11VwAGrQanCaexGVmBafSbTs1X2l165eyb+m8uN/mg"},
					{"another", "$scrypt$ln=15,r=8,p=1$8l6LsXbOWSsl5FxrrRUCQA$QREuVEonX9xZ6hyM/03VrukPdDpmO6J+7dOAtdSnXOs"},
					{"th15isalongandcomplexpassw0rd@", "$scrypt$ln=15,r=8,p=1$rXVOqRWidE7pnRNirHVu7Q$07GRj2tCUsvDTJoC2gKIjCaFKxJ7TCXOE0BqAwOu4kA"},
					{"password123", "$scrypt$ln=15,r=8,p=1$r9Va6x3jPMeYs/Y+x7hXag$LGeP1nUa5cTTQIjw+tNOK2byz/e4HBSQe6Skn8132bE"},
					{"p@ssw0rd", "$scrypt$ln=15,r=8,p=1$sZZyTglBqJUSQqi19j7HuA$WNyijpd/R2LfYS97Yb/lnmSnoarTMPt3l2JQ9XhVMo4"},
				},
			},
			{
				name: "argon2i",
				passwords: []testPassword{
					{"apple123", "$argon2i$v=19$m=65536,t=4,p=4$cU6JsTZGCEEoxRjD+L/3/g$RyLxXgYks/RplDoRKaxvZDJBvrS7R6vGeusKrfXP0Pg"},
					{"another", "$argon2i$v=19$m=65536,t=4,p=4$DCHk/B+DcI7xHsP4/7/XWg$6luPgx9bGrYQR0oJdNVfsE85zr0AECdD6RHHgRKHG3M"},
					{"th15isalongandcomplexpassw0rd@", "$argon2i$v=19$m=65536,t=4,p=4$D6H0HmOs1ZpzDkHoXQvh/A$xQK6H91LeP5ZLv7PHFMpVYHbAgEKB3gnh/0z0ScJRow"},
					{"password123", "$argon2i$v=19$m=65536,t=4,p=4$NcaYs3bufQ8BwPhfSyklBA$Iuz9GZw5AUrXQ32Z4poJ3COUTp4w0amWRA6XtMnB5pw"},
					{"p@ssw0rd", "$argon2i$v=19$m=65536,t=4,p=4$t7a2lhKCsBYC4HxPCcH4nw$zhSHktwftzV0aL6MgsN2eiZTa7gq8yFiHxJaomEeNfo"},
				},
			},
			{
				name: "argon2d",
				passwords: []testPassword{
					{"apple123", "$argon2d$v=19$m=65536,t=4,p=4$PUfIWctZa611rpXSOicEAA$eUtgGpyO1+ylLPGhN8gvRXBXF+Zd97kQIZA7OgX4VIM"},
					{"another", "$argon2d$v=19$m=65536,t=4,p=4$j5GyNoaQsvYeA8D4Pyek9A$O1LC/BW/nF2/PkgSR2/O62q5ERTXxvIVvBFgeN4REUw"},
					{"th15isalongandcomplexpassw0rd@", "$argon2d$v=19$m=65536,t=4,p=4$+j8H4BzjvPeeEwKglDLGWA$6OmSgnEaAi+HrvMiMmHhuCMK/9s8zg0KJepXUP8QKFo"},
					{"password123", "$argon2d$v=19$m=65536,t=4,p=4$QMi5VwrhvBeiVCplDKEUAg$BbFZ3C+ptJO7DhzBIxit9e1ZI7uk9KG5n1kpTZf6ZwQ"},
					{"p@ssw0rd", "$argon2d$v=19$m=65536,t=4,p=4$25tzbs1ZCwEAAGCMEYJQyg$OlkYC6K4I/X4UJmMC0qecqUwVwLvkT05eje92iumf8E"},
				},
			},
			{
				name: "argon2id",
				passwords: []testPassword{
					{"apple123", "$argon2id$v=19$m=65536,t=4,p=4$jfE+JyTE2DtnDCHknJOSsg$+BPKo7PFUjKycwSpEK0Z1ciUPKp05uJvSfC7C+QAvAk"},
					{"another", "$argon2id$v=19$m=65536,t=4,p=4$FGJszRlDyDmntJbyHoNQag$iGKvD7Oso+PcRhSVT/q/QCRb/mNZL0cwbtCKMzW/NPw"},
					{"th15isalongandcomplexpassw0rd@", "$argon2id$v=19$m=65536,t=4,p=4$qvU+J6Q0xnivdS5FSMm5Fw$SpP3dXG6xTUcSxGrj+GTtWCFzekltzUodkIcPuX0KhY"},
					{"password123", "$argon2id$v=19$m=65536,t=4,p=4$rXUOwdg7x3iPkRKCMKZUSg$FgvrlMTstAr9BhVS2yYM/Of68HzCCJGqfgtQ2cGEY1w"},
					{"p@ssw0rd", "$argon2id$v=19$m=65536,t=4,p=4$15pzjpHSulfKuTcmREjJmQ$xcc8g7C4a9ErFLdjNDKZAvgH6su3s+UEuRYekZpr/9s"},
				},
			},
			{
				name: "pbkdf2",
				passwords: []testPassword{
					{"apple123", "$pbkdf2$131000$OMd4jxFCqFWq9T7HWEvpvQ$MniJ8FEvDtukO8KmKYM1yUV0VWk"},
					{"another", "$pbkdf2$131000$NIYwJmQsBaCUUiqlFOJcyw$N4z4kukUf7ZB455b.MER2XGuROg"},
					{"th15isalongandcomplexpassw0rd@", "$pbkdf2$131000$AoDwvndOCSHEuLcWYowxxg$dviIy2JvGQ64f.aKct/q5NzfWqE"},
					{"password123", "$pbkdf2$131000$ay3FOEdoLQWA0Frr/b83Rg$ZfhrII96N/ysF7yNKHNziHC34E4"},
					{"p@ssw0rd", "$pbkdf2$131000$DKE0RihlbK21di4lREiptQ$jSUw1ovAsF6hSfoj1FMsN3YrlRE"},
				},
			},
		},
	},
	{
		name: "OpenLDAP",
		algorithms: []testAlgorithm{
			{
				name: "pbkdf2",
				passwords: []testPassword{
					{"apple123", "{PBKDF2}10000$uPfpfTXP3NX9tQ0a/p5VaQ$Ag4JdbL6t05DuprdvlkEQsrWo4k"},
				},
			},
			{
				name: "pbkdf2-sha256",
				passwords: []testPassword{
					{"apple123", "{PBKDF2-SHA256}10000$xxOL0cKNcEfejM9hoWFBCA$gTSqXH8dHrh9AkV2To5S56NIPRh2G8XBQlb1MhcyeHM"},
				},
			},
			{
				name: "pbkdf2-sha512",
				passwords: []testPassword{
					{"apple123", "{PBKDF2-SHA512}10000$1hggvWEtcJ0AGI5lT57d9A$q1epGDAulI/5Dz426cvJW7GXGmEksiSQmZ3AnQ5fB3FyXkglyOoi1F5kcPeMVQK9RabR6T1T7ANjaEZCxMdpmA"},
				},
			},
			{
				name: "argon2i",
				passwords: []testPassword{
					{"apple123", "{ARGON2}$argon2i$v=19$m=4096,t=3,p=1$pheUpIlJos7rsy3eS7fapw$L7+pHSnGtABP5eoVkQ+s8MsuYAKKzOKsTOyUv1vvqsg"},
				},
			},
		},
	},
}
