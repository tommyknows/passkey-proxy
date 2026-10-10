// Package session issues and verifies signed session cookies.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const cookieName = "passkey_session"

var (
	encoding   = base64.RawURLEncoding
	errInvalid = errors.New("session: invalid cookie")
)

// Signer issues session cookies and authenticates requests.
type Signer struct {
	key    []byte
	ttl    time.Duration
	domain string
	secure bool
}

// NewSigner creates a signer with the given cookie lifetime and scope.
// An empty domain restricts cookies to the issuing host.
// Signers sharing a key accept each other's cookies.
func NewSigner(key []byte, ttl time.Duration, domain string, secure bool) *Signer {
	return &Signer{key: key, ttl: ttl, domain: domain, secure: secure}
}

// Cookie returns a signed session cookie for name.
func (s *Signer) Cookie(name string) *http.Cookie {
	// Put the name last so dots in usernames need no escaping.
	body := strconv.FormatInt(time.Now().Add(s.ttl).Unix(), 10) + "." + name
	return &http.Cookie{
		Name:     cookieName,
		Value:    encoding.EncodeToString(s.sign(body)) + "." + body,
		Path:     "/",
		Domain:   s.domain,
		MaxAge:   int(s.ttl.Seconds()),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// Authenticate the request given the cookie and return the username from it.
// Missing, invalid, and expired cookies return an error.
func (s *Signer) Authenticate(r *http.Request) (string, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", errInvalid
	}

	encodedSignature, body, ok := strings.Cut(c.Value, ".")
	if !ok {
		return "", errInvalid
	}

	signature, err := encoding.DecodeString(encodedSignature)
	if err != nil {
		return "", errInvalid
	}

	if !hmac.Equal(signature, s.sign(body)) {
		return "", errInvalid
	}

	expiresAt, name, ok := strings.Cut(body, ".")
	if !ok {
		return "", errInvalid
	}

	expiry, err := strconv.ParseInt(expiresAt, 10, 64)
	if err != nil {
		return "", errInvalid
	}

	if time.Now().After(time.Unix(expiry, 0)) {
		return "", errInvalid
	}

	strip(r)

	return name, nil
}

func (s *Signer) sign(body string) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(body))
	return mac.Sum(nil)
}

// strip removes the session cookie from r, keeping all other cookies as-is,
// so that the upstream cannot re-use the cookie.
func strip(r *http.Request) {
	var kept []string
	for _, line := range r.Header.Values("Cookie") {
		for part := range strings.SplitSeq(line, ";") {
			part = strings.TrimSpace(part)
			name, _, _ := strings.Cut(part, "=")
			if part != "" && name != cookieName {
				kept = append(kept, part)
			}
		}
	}
	r.Header.Del("Cookie")
	if len(kept) > 0 {
		r.Header.Set("Cookie", strings.Join(kept, "; "))
	}
}
