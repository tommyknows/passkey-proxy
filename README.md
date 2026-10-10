# passkey-proxy

Very basic reverse-proxy that puts the backed server behind a passkey login.
Passkeys are the only auth method, and user registration is allowed only when
explicitly enabled.

Adds an `X-Auth-User` header to the forwarded requests with the username.
The proxy's own session cookie is stripped before forwarding.

Sessions are HMAC-signed cookies, so that multiple instances of the proxy can
share a signing key and thus an authenticated session, for example to back
multiple different servers behind one login.

## Configuration

| Variable                | Default                 | Description                                                                                                                      |
| ----------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `PASSKEY_RPID`          | (required)              | The relying party ID: the **registrable domain**, e.g. `example.com`. Baked into every passkey permanently and can never change. |
| `PASSKEY_ORIGIN`        | (required)              | The public origin the browser loads, e.g. `https://app.example.com`. Checked on every ceremony, so this may change.              |
| `PASSKEY_SESSION_KEY`   | random                  | Secret to sign session cookies. If unset, a random key is generated at startup.                                                  |
| `PASSKEY_COOKIE_DOMAIN` | unset                   | The cookie's `Domain` attribute. Set it to the parent domain (`example.com`) to share a login across subdomains.                 |
| `PASSKEY_LISTEN`        | `:9090`                 | Address to listen on.                                                                                                            |
| `PASSKEY_FORWARD`       | `http://localhost:9091` | The app to proxy to, as a full URL.                                                                                              |
| `PASSKEY_FILE`          | `passkeys.json`         | File where the passkeys are stored & read from.                                                                                  |
| `PASSKEY_ENROLL`        | unset                   | Account name to enroll. See below. Leave unset in normal operation.                                                              |

## Enrolling a passkey

To create a passkey / add a user to the passkey-proxy, set the
`PASSKEY_ENROLL=<user>` environment variable. This will expose
`$PASSKEY_LISTEN/auth/enroll`, at which you can register a new passkey.
The proxy will log a one-time enrollment token at startup which needs to be
provided during the enrollment. Once that one-time token is spent, enrollment
automatically closes until the next restart.

## Running several instances

Use the **same** `PASSKEY_RPID`, `PASSKEY_SESSION_KEY` and
`PASSKEY_COOKIE_DOMAIN` variables for every instance to expose multiple
auth-proxies sharing a login:

```sh
export PASSKEY_RPID="example.com" \
    PASSKEY_SESSION_KEY=$(openssl rand -hex 32) \
    PASSKEY_COOKIE_DOMAIN="example.com"

PASSKEY_ORIGIN=https://one.example.com PASSKEY_LISTEN=127.0.0.1:9090 \
PASSKEY_FORWARD=http://localhost:9091 passkey-proxy

PASSKEY_ORIGIN=https://two.example.com PASSKEY_LISTEN=127.0.0.1:9092 \
PASSKEY_FORWARD=http://localhost:9093 passkey-proxy
```

## Local development

```sh
PASSKEY_RPID=localhost \
PASSKEY_ORIGIN=http://localhost:9090 \
PASSKEY_ENROLL=my-user \
go run .
```

If the proxy's origin is http, the cookie is not marked as `Secure` so that it
is sent by the browser anyways. Note that browsers only treat `localhost` as
secure without TLS, so this setup does not work on other domains.

## Security notes

- The PASSKEY_FILE does not contain secrets, only public verification material.
- The PASSKEY_SESSION_KEY is **secret**, store it like a private key.
- Don't host untrusted apps on PASSKEY_COOKIE_DOMAIN, since otherwise a cookie
  forwarded to an untrusted app could be re-used by that app to forge requests.
- Since this proxy does not speak HTTPS, it should always be fronted by an
  HTTPS-terminating proxy like nginx.
- Once a user is logged in, their session **cannot** be revoked unless the full
  session key is rotated, causing everyone else to also be logged out.
