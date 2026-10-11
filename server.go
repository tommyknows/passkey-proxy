package main

import (
	"crypto/subtle"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"

	"filippo.io/passkey"

	"github.com/tommyknows/passkey-proxy/internal/session"
	"github.com/tommyknows/passkey-proxy/internal/store"
)

var (
	//go:embed web/login.html
	loginHTML []byte

	//go:embed web/enroll.html
	enrollHTML []byte

	//go:embed web/style.css
	styleCSS []byte
)

const (
	// maxPendingChallenges bounds the memory unauthenticated clients can use.
	maxPendingChallenges = 100

	// maxBodySize is far above any real passkey response.
	maxBodySize = 64 << 10
)

type server struct {
	relyingParty *passkey.RelyingParty
	accounts     *store.Store
	// proxy is optional - if unset requests are not forwarded.
	proxy *httputil.ReverseProxy

	origin string

	enrollName, enrollUserID, enrollToken string

	sessions *session.Signer

	challenges loginChallenges
}

func (s *server) handler() (http.Handler, error) {
	auth := http.NewServeMux()
	auth.HandleFunc("POST /auth/login/options", s.loginOptions)
	auth.HandleFunc("POST /auth/login", s.login)
	if s.enrollName != "" {
		auth.HandleFunc("GET /auth/enroll/{$}", s.enrollPage)
		auth.HandleFunc("POST /auth/enroll/options", s.requireEnrollToken(s.enrollOptions))
		auth.HandleFunc("POST /auth/enroll", s.requireEnrollToken(s.enroll))
	}
	auth.HandleFunc("GET /auth/style.css", stylesheet)
	auth.HandleFunc("/", s.loginPage)

	csrf := http.NewCrossOriginProtection()
	// The public origin may differ from Host behind a reverse proxy.
	if err := csrf.AddTrustedOrigin(s.origin); err != nil {
		return nil, fmt.Errorf("PASSKEY_ORIGIN: %w", err)
	}
	h := csrf.Handler(auth)

	// wrap any incoming request, sending the login-page if the session cookie
	// is not present, but otherwise preserving upstream paths.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, err := s.sessions.Authenticate(r)
		if err != nil {
			h.ServeHTTP(w, r)
			return
		}

		if s.proxy != nil {
			r.Header.Set("X-Auth-User", name)
			s.proxy.ServeHTTP(w, r)
			return
		}

		w.Header().Set("X-Auth-User", name)
		w.WriteHeader(http.StatusNoContent)
		return

	}), nil
}

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	// login page is served for every request that is unauthenticated, we need to provide
	// sensible errors for users that do not execute a GET text/html like `curl`.
	if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write(loginHTML)
}

func (s *server) loginOptions(w http.ResponseWriter, r *http.Request) {
	request, optionsJSON, err := s.relyingParty.NewLogin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.challenges.add(passkey.RequestID(request), request)
	w.Write(optionsJSON)
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	responseJSON, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
	if err != nil {
		loginFailed(w, http.StatusBadRequest, "reading request: %v", err)
		return
	}

	response, err := passkey.ParseResponse(responseJSON)
	if err != nil {
		loginFailed(w, http.StatusBadRequest, "parsing response: %v", err)
		return
	}

	request, found := s.challenges.take(response.RequestID())
	if !found {
		loginFailed(w, http.StatusUnauthorized, "unknown or expired challenge")
		return
	}

	// The unverified user ID selects a candidate; Login authenticates it.
	userID := response.UnauthenticatedUserID()
	user, known := s.accounts.Lookup(userID)
	if !known {
		loginFailed(w, http.StatusUnauthorized, "no account for user ID %q", userID)
		return
	}
	if len(user.Passkeys) == 0 {
		loginFailed(w, http.StatusUnauthorized, "account %q has no enrolled passkey", user.Name)
		return
	}

	if _, err := s.relyingParty.Login(response, request, user.Passkeys); err != nil {
		loginFailed(w, http.StatusUnauthorized, "verifying passkey for %q: %v", user.Name, err)
		return
	}

	http.SetCookie(w, s.sessions.Cookie(user.Name))
}

// loginFailed logs why a login failed but keeps the reason from the client,
// so responses do not reveal which accounts or passkeys exist.
func loginFailed(w http.ResponseWriter, status int, format string, args ...any) {
	log.Printf("login failed: "+format, args...)
	http.Error(w, "Unknown or invalid passkey", status)
}

func (s *server) enrollPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(enrollHTML)
}

// requireEnrollToken rejects requests without the enrollment token.
func (s *server) requireEnrollToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Enroll-Token")), []byte(s.enrollToken)) != 1 {
			log.Printf("enrollment rejected: invalid or used token")
			http.Error(w, "invalid enrollment token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *server) enrollOptions(w http.ResponseWriter, r *http.Request) {
	var existing []string
	// When replacing, let the authenticator overwrite its own old passkey.
	if r.URL.Query().Get("replace") == "" {
		user, _ := s.accounts.Lookup(s.enrollUserID)
		existing = user.Passkeys
	}

	optionsJSON, err := s.relyingParty.NewRegistration(
		passkey.User{ID: s.enrollUserID, Name: s.enrollName},
		existing,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(optionsJSON)
}

func (s *server) enroll(w http.ResponseWriter, r *http.Request) {
	responseJSON, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
	if err != nil {
		http.Error(w, "enrollment failed", http.StatusBadRequest)
		return
	}

	record, err := s.relyingParty.Register(responseJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	replace := r.URL.Query().Get("replace") != ""
	if err := s.accounts.AddPasskey(s.enrollUserID, record, replace); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if replace {
		log.Printf("removed old passkeys for %q", s.enrollName)
	}
	log.Printf("enrolled new passkey for %q; unset PASSKEY_ENROLL and restart", s.enrollName)
}

// loginChallenges holds single-use login challenges. Its zero value is ready to use.
type loginChallenges struct {
	mu      sync.Mutex
	pending map[string][]byte
}

func (c *loginChallenges) add(id string, request []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pending == nil {
		c.pending = map[string][]byte{}
	}

	if len(c.pending) >= maxPendingChallenges {
		clear(c.pending)
	}

	c.pending[id] = request
}

func (c *loginChallenges) take(id string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	request, ok := c.pending[id]

	delete(c.pending, id)
	return request, ok
}

func stylesheet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write(styleCSS)
}
