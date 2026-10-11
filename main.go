// Command passkey-proxy serves an app behind a passkey login.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"filippo.io/passkey"

	"github.com/tommyknows/passkey-proxy/internal/session"
	"github.com/tommyknows/passkey-proxy/internal/store"
)

const (
	defaultListenAddr  = ":9090"
	defaultPasskeyFile = "passkeys.json"
)

// sessionTTL determines the cookie TTL, which defines when a user has to re-authenticate.
const sessionTTL = 8 * time.Hour

const shutdownTimeout = 10 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func run(ctx context.Context) error {
	origin := os.Getenv("PASSKEY_ORIGIN")
	relyingParty, err := passkey.NewRelyingParty(&passkey.Options{
		RPID:   os.Getenv("PASSKEY_RPID"),
		Origin: origin,
	})
	if err != nil {
		return err
	}

	// Plain HTTP is for localhost development; Secure cookies require HTTPS.
	secure := !strings.HasPrefix(origin, "http://")
	if !secure {
		log.Printf("origin is %s: session cookie is not Secure, use this only locally", origin)
	}

	accounts, err := store.Load(envOrDefault("PASSKEY_FILE", defaultPasskeyFile))
	if err != nil {
		return err
	}

	enrollUser := os.Getenv("PASSKEY_ENROLL")
	var enrollToken string
	if enrollUser != "" {
		enrollToken = rand.Text()
		log.Printf("enrollment open for %q at /auth/enroll with token %s", enrollUser, enrollToken)
	}

	var proxy *httputil.ReverseProxy
	if upstreamURL := os.Getenv("PASSKEY_FORWARD"); upstreamURL != "" {
		upstream, err := url.Parse(upstreamURL)
		if err != nil {
			return fmt.Errorf("PASSKEY_FORWARD: %w", err)
		}

		proxy = httputil.NewSingleHostReverseProxy(upstream)
		log.Printf("forwarding to %s", upstreamURL)
	}

	key, err := sessionKey(os.Getenv("PASSKEY_SESSION_KEY"), os.Getenv("PASSKEY_COOKIE_DOMAIN"))
	if err != nil {
		return err
	}

	s := &server{
		relyingParty: relyingParty,
		proxy:        proxy,
		accounts:     accounts,
		origin:       origin,
		enrollName:   enrollUser,
		enrollToken:  enrollToken,
		sessions: session.NewSigner(key, sessionTTL,
			os.Getenv("PASSKEY_COOKIE_DOMAIN"), secure),
	}
	if enrollUser != "" {
		s.enrollUserID = accounts.User(enrollUser)
	}

	h, err := s.handler()
	if err != nil {
		return err
	}

	return serve(ctx, envOrDefault("PASSKEY_LISTEN", defaultListenAddr), h)
}

func sessionKey(key, cookieDomain string) ([]byte, error) {
	if key != "" {
		return []byte(key), nil
	}

	if cookieDomain != "" {
		return nil, errors.New("PASSKEY_SESSION_KEY is required with PASSKEY_COOKIE_DOMAIN, " +
			"so that every instance accepts the same sessions")
	}

	// This also causes users to be logged out on proxy restart.
	log.Print("PASSKEY_SESSION_KEY unset: using a random key")
	return []byte(rand.Text()), nil
}

func serve(ctx context.Context, addr string, h http.Handler) error {
	// No ReadTimeout or WriteTimeout, as they would cut off long-running
	// upstream requests like downloads or websockets.
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}

	errc := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", addr)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	log.Printf("shutting down, waiting up to %s for requests to finish", shutdownTimeout)
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Print("stopped")
	return nil
}
