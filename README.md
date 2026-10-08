# oidcgate

OpenID Connect login for any `net/http` Go app, in two lines, configured
entirely by environment variables.

```go
gate, err := oidcgate.FromEnv(ctx, "myapp") // reads MYAPP_OIDC_* env vars
if err != nil {
	log.Fatal(err) // OIDC enabled but misconfigured: refuse to start
}
handler = gate.Wrap(handler) // no-op when OIDC is not enabled
```

`Wrap` adds `/auth/login`, `/auth/callback`, `/auth/logout` and
`/auth/logged-out`, and requires a signed-in user for every other path.
No front-end changes are needed:

- **Browser page loads** without a session are redirected to the IdP and
  returned to the page they asked for.
- **Everything else** (fetch/XHR, API clients) gets `401 {"error":"unauthorized"}`.

Handlers behind the gate can read the user:

```go
if u, ok := oidcgate.UserFrom(r.Context()); ok { _ = u.Email }
```

## Environment variables

`<APP>` is the name you pass to `FromEnv`, upper-cased, with anything that is
not a letter or digit replaced by `_` (`"my-app"` → `MY_APP`).

| Variable | | |
|---|---|---|
| `<APP>_OIDC_ENABLED` | | `true` turns OIDC on. Unset or `false`: the gate is off and nothing changes. |
| `<APP>_OIDC_ISSUER` | required | IdP issuer URL, e.g. `https://auth.example.com`. |
| `<APP>_OIDC_CLIENT_ID` | required | Client ID registered at the IdP. |
| `<APP>_OIDC_CLIENT_SECRET` | required | Client secret (plaintext; the IdP may store only a hash). |
| `<APP>_OIDC_BASE_URL` | required | External URL of the app, no path: `https://myapp.example.com`. |
| `<APP>_OIDC_SESSION_SECRET` | optional | Signs the session cookie, min 16 chars. Unset: random per start, so sessions end on restart. |
| `<APP>_OIDC_PUBLIC_PATHS` | optional | Comma-separated paths that skip auth, added to `/healthz`. A trailing `/` makes it a prefix. |

If OIDC is enabled and anything required is missing, or the issuer cannot be
reached, `FromEnv` returns an error. The app should exit rather than serve
unauthenticated.

## At the IdP

Register the app as a confidential client:

- Redirect URI: `<BASE_URL>/auth/callback` (logged at startup)
- Scopes: `openid profile email`
- Token endpoint auth: `client_secret_basic` (PKCE `S256` is always used)

**Who may sign in is decided at the IdP**, not here: Authelia access policy /
`authorization_policy`, Entra "Assignment required", Keycloak client roles,
and so on. Any user the IdP authenticates for this client is let in.

Example Authelia client (check keys against your Authelia version):

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: myapp
        client_name: MyApp
        client_secret: '$pbkdf2-sha512$...'   # hash of MYAPP_OIDC_CLIENT_SECRET
        public: false
        authorization_policy: two_factor
        redirect_uris: ['https://myapp.example.com/auth/callback']
        scopes: [openid, profile, email]
        token_endpoint_auth_method: client_secret_basic
```

## How it works

- Authorization code flow with PKCE (S256), `state` and `nonce`; the ID token
  is verified (signature, issuer, audience, expiry, nonce) with
  [go-oidc](https://github.com/coreos/go-oidc).
- The session is a stateless HMAC-signed cookie (`HttpOnly`, `SameSite=Lax`,
  `Secure` when `BASE_URL` is https) with a sliding 7-day lifetime. No server
  store, no Redis. Cookies are namespaced by app name, so apps on one host
  don't see each other's sessions.
- Login failures are logged with detail server-side; the user sees only a
  generic message. Tokens and secrets are never logged.
- `/auth/logout` clears the local session only; it does not end the IdP's
  SSO session.

## Limits

- `BASE_URL` must not contain a path (no sub-path hosting).
- Signing the same app in from several hosts needs one client per host.
- Cookie `SameSite=Lax` is the CSRF defence for state-changing requests.

## Options

For the rare case the environment isn't enough:
`oidcgate.WithPublicPaths(...)`, `WithSessionTTL(d)`, `WithLogger(l)`; or build
a `Config` and call `oidcgate.New(ctx, cfg)`.

## Testing

`go test -race ./...` runs the whole flow against an in-process fake IdP;
nothing talks to a real provider.
