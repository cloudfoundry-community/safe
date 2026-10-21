// Pins the crypt-md5, crypt-sha256, and crypt-sha512 outputs of secret.go to
// vectors that do not come from the crypt library, so that swapping or
// vendoring the tredoe osutil module can be proven byte-compatible.
package vault

import "testing"

func TestCryptWithSaltVectors(t *testing.T) {
	// The long salt cases pass 16 letters, as the public path does. The md5
	// scheme only uses the first 8 of them.
	tests := []struct {
		name string
		fn   func(pass, salt string) (string, error)
		pass string
		salt string
		want string
	}{
		// Generated with: openssl passwd -1 -salt <salt> <password>
		{"md5", cryptMD5WithSalt, "password", "saltsalt", "$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/"},
		{"md5 long salt", cryptMD5WithSalt, "s3cret-pw", "abcdefghijklmnop", "$1$abcdefgh$qfrUSDGDksusUHn3b/aFr0"},
		// Generated with: openssl passwd -5 -salt <salt> <password>
		{"sha256", cryptSHA256WithSalt, "password", "saltsalt", "$5$saltsalt$gOjOtoMpVhru2uyjeJSEc/JaLQWOXMNmlOnj6T4AtC."},
		{"sha256 long salt", cryptSHA256WithSalt, "s3cret-pw", "abcdefghijklmnop", "$5$abcdefghijklmnop$AN86.Jxoq4h65Kg5lTkzZv/qGNj5ihwoDHGJjjkdtE4"},
		// Generated with: openssl passwd -6 -salt <salt> <password>
		{"sha512", cryptSHA512WithSalt, "password", "saltsalt", "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"},
		{"sha512 long salt", cryptSHA512WithSalt, "s3cret-pw", "abcdefghijklmnop", "$6$abcdefghijklmnop$JAdOPMTmBKNDAmk1gF/./sEbECW4cOVIk7SfGEdhSLHiZYq6NN48ppIwGMdpKnN5CU0h0jjfNTOhNmjesfG.y."},
		// Reference vector from the SHA-crypt specification, section 5,
		// https://www.akkadia.org/drepper/SHA-crypt.txt. The salt is cut to
		// 16 characters in the output.
		{"sha512 rounds", cryptSHA512WithSalt, "Hello world!", "rounds=10000$saltstringsaltstring", "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fn(tt.pass, tt.salt)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
