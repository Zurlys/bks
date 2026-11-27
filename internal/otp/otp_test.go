package otp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors (8 digits).
func TestRFC6238Vectors(t *testing.T) {
	seeds := map[string]string{
		"SHA1":   "12345678901234567890",
		"SHA256": "12345678901234567890123456789012",
		"SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
	}
	want := map[string][]string{
		"SHA1":   {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"},
		"SHA256": {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"},
		"SHA512": {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"},
	}
	times := []int64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
	for alg, seed := range seeds {
		uri := "otpauth://totp/test?digits=8&algorithm=" + alg + "&secret=" + base32.StdEncoding.EncodeToString([]byte(seed))
		tp, err := Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		for i, ts := range times {
			if got := tp.Code(time.Unix(ts, 0)); got != want[alg][i] {
				t.Errorf("%s at %d = %s, want %s", alg, ts, got, want[alg][i])
			}
		}
	}
}

func TestDefaultsAndRemaining(t *testing.T) {
	tp, err := Parse("otpauth://totp/GitHub:jonas?secret=jbsw y3dp-ehpk3pxp&issuer=GitHub")
	if err != nil {
		t.Fatal(err)
	}
	if tp.Digits != 6 || tp.Period != 30 || tp.Algorithm != "SHA1" || tp.Issuer != "GitHub" || tp.Label != "GitHub:jonas" {
		t.Fatalf("defaults: %+v", tp)
	}
	if c := tp.Code(time.Unix(0, 0)); len(c) != 6 {
		t.Fatalf("code %q", c)
	}
	if r := tp.Remaining(time.Unix(61, 500_000_000)); r != 28500*time.Millisecond {
		t.Fatalf("remaining %v", r)
	}
}

func TestParseRejects(t *testing.T) {
	for _, uri := range []string{
		"https://example.com/?secret=JBSWY3DP",
		"otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
		"otpauth://totp/x",
		"otpauth://totp/x?secret=not-base32!",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
	} {
		if _, err := Parse(uri); err == nil {
			t.Errorf("accepted %s", uri)
		}
	}
}

func TestNormalize(t *testing.T) {
	// bare secret, as printed under "can't scan the code?"
	got, err := Normalize("jbsw y3dp ehpk 3pxp", "GitLab (work)")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "otpauth://totp/GitLab%20%28work%29?secret=JBSWY3DPEHPK3PXP") {
		t.Fatalf("got %s", got)
	}
	// a URI round-trips to the same codes, defaults dropped
	in := "otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&issuer=A&digits=8&period=60&algorithm=sha256"
	out, err := Normalize(in, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := Parse(in)
	b, _ := Parse(out)
	now := time.Now()
	if a.Code(now) != b.Code(now) || b.Digits != 8 || b.Period != 60 || b.Algorithm != "SHA256" {
		t.Fatalf("round trip changed codes: %s", out)
	}
	if _, err := Normalize("  ", "x"); err == nil {
		t.Error("accepted empty secret")
	}
}
