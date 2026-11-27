// Package otp computes time-based one-time passwords (RFC 6238) from
// otpauth:// URIs, the format inside 2FA QR codes.
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TOTP is a parsed otpauth://totp URI.
type TOTP struct {
	Secret    []byte
	Algorithm string // SHA1, SHA256 or SHA512
	Digits    int
	Period    int // seconds
	Label     string
	Issuer    string
}

// Parse reads an otpauth://totp/... URI. HOTP (counter-based) URIs are
// rejected: bks only does time-based codes.
func Parse(uri string) (TOTP, error) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil || !strings.EqualFold(u.Scheme, "otpauth") {
		return TOTP{}, errors.New("not an otpauth:// URI")
	}
	if !strings.EqualFold(u.Host, "totp") {
		return TOTP{}, fmt.Errorf("only time-based (totp) codes are supported, not %q", u.Host)
	}
	q := u.Query()
	t := TOTP{Algorithm: "SHA1", Digits: 6, Period: 30, Label: strings.TrimPrefix(u.Path, "/"), Issuer: q.Get("issuer")}
	if t.Secret, err = decodeSecret(q.Get("secret")); err != nil {
		return TOTP{}, err
	}
	if a := q.Get("algorithm"); a != "" {
		t.Algorithm = strings.ToUpper(a)
	}
	if hashFor(t.Algorithm) == nil {
		return TOTP{}, fmt.Errorf("unsupported algorithm %q", t.Algorithm)
	}
	if d := q.Get("digits"); d != "" {
		if t.Digits, err = strconv.Atoi(d); err != nil || t.Digits < 6 || t.Digits > 8 {
			return TOTP{}, fmt.Errorf("digits must be 6-8, got %q", d)
		}
	}
	if p := q.Get("period"); p != "" {
		if t.Period, err = strconv.Atoi(p); err != nil || t.Period < 10 || t.Period > 300 {
			return TOTP{}, fmt.Errorf("period must be 10-300 seconds, got %q", p)
		}
	}
	return t, nil
}

// Normalize accepts an otpauth:// URI or a bare base32 secret (as shown
// under "can't scan the QR code?") and returns a validated, canonical URI.
// label names the account for a bare secret.
func Normalize(input, label string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", errors.New("empty OTP secret")
	}
	if strings.Contains(input, "://") {
		t, err := Parse(input)
		if err != nil {
			return "", err
		}
		return t.URI(), nil
	}
	secret, err := decodeSecret(input)
	if err != nil {
		return "", err
	}
	return TOTP{Secret: secret, Algorithm: "SHA1", Digits: 6, Period: 30, Label: label}.URI(), nil
}

// URI is the canonical otpauth URI; default parameters are left out.
func (t TOTP) URI() string {
	q := url.Values{}
	q.Set("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.Secret))
	if t.Issuer != "" {
		q.Set("issuer", t.Issuer)
	}
	if t.Algorithm != "" && t.Algorithm != "SHA1" {
		q.Set("algorithm", t.Algorithm)
	}
	if t.Digits != 0 && t.Digits != 6 {
		q.Set("digits", strconv.Itoa(t.Digits))
	}
	if t.Period != 0 && t.Period != 30 {
		q.Set("period", strconv.Itoa(t.Period))
	}
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + t.Label, RawQuery: q.Encode()}
	return u.String()
}

// Code returns the code valid at time at.
func (t TOTP) Code(at time.Time) string {
	sec := at.Unix()
	if sec < 0 {
		sec = 0
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(sec)/uint64(t.Period))
	mac := hmac.New(hashFor(t.Algorithm), t.Secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < t.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", t.Digits, bin%mod)
}

// Remaining is how long the code at time at stays valid.
func (t TOTP) Remaining(at time.Time) time.Duration {
	p := int64(t.Period)
	ms := at.UnixMilli()
	return time.Duration(p*1000-ms%(p*1000)) * time.Millisecond
}

func hashFor(alg string) func() hash.Hash {
	switch alg {
	case "SHA1":
		return sha1.New
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	}
	return nil
}

// decodeSecret reads base32 leniently: any case, spaces or dashes between
// groups, padding optional.
func decodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(s))
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, errors.New("OTP secret is missing")
	}
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, errors.New("OTP secret is not valid base32")
	}
	return b, nil
}
