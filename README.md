# oidcgate

Login for any `net/http` Go app, in two lines, configured by environment
variables: a local account created on first launch, plus optional OpenID
Connect (Authelia, Authentik, Keycloak, Entra ID, …).

```go
gate, err := oidcgate.FromEnv(ctx, "myapp") // reads MYAPP_* env vars
if err != nil {
	log.Fatal(err) // misconfigured: refuse to start rather than serve unprotected
}
handler = gate.Wrap(handler) // no-op when the gate is off
```

The gate owns everything about authentication: the login, setup and error
pages, the local account, sessions, the OIDC flow, and the routes under
`/auth/`. **The app has no code for any of it.** Remove the two lines and the
app has no idea an account ever existed.

The gate is **on by default**. Apps that deliberately sit behind forward auth
set `MYAPP_AUTH_DISABLED=true`; `FromEnv` then returns `nil`, and
`(*Gate)(nil).Wrap` returns the handler unchanged.

## How a visit is routed

A request without a session is routed like this (browser page loads are
redirected; `fetch`/XHR and API clients get `401 {"error":"unauthorized"}`):

| Account exists? | OIDC configured? | What happens |
|---|---|---|
| no | yes | Redirect to the IdP. No local account is created, and `/auth/setup` is closed. |
| no | no | **Create your account** page (first launch). |
| yes | yes | Redirect to the IdP first. |
| yes | no | Local login page. |

If the IdP does not approve the login (denied, or any failure), the gate shows:

- the **local login form** plus a *Try again with OpenID Connect* button, if an
  account exists and local login is enabled; or
- an **error page** with *Try again*, otherwise (no account, or local login
  disabled).

It never redirects to the IdP again while showing that page, so a rejection
cannot loop.

`/auth/login` is always reachable directly. If the IdP is down, go there to
use the local account.

**IdP unreachable at startup is not fatal.** The gate starts anyway, retries
discovery in the background (5 s, doubling to 1 min), and until the provider
answers, behaves as if OIDC were not available: the local login works. Once
the provider is reachable it starts redirecting to it.

## Environment variables

`<APP>` is the name you pass to `FromEnv`, upper-cased, with anything that is
not a letter or digit replaced by `_` (`"my-app"` → `MY_APP`).

| Variable | | |
|---|---|---|
| `<APP>_AUTH_DISABLED` | | `true`: no gate at all (the app relies on something else, e.g. forward auth). |
| `<APP>_AUTH_PUBLIC_PATHS` | optional | Comma-separated paths that skip auth, added to `/healthz`. A trailing `/` makes it a prefix. |
| `<APP>_OIDC_ENABLED` | | `true` turns OIDC login on. |
| `<APP>_OIDC_ISSUER` | with OIDC | IdP issuer URL, e.g. `https://auth.example.com`. |
| `<APP>_OIDC_CLIENT_ID` | with OIDC | Client ID registered at the IdP. |
| `<APP>_OIDC_CLIENT_SECRET` | with OIDC | Client secret (plaintext; the IdP may store only a hash). |
| `<APP>_OIDC_BASE_URL` | with OIDC | External URL of the app, no path: `https://myapp.example.com`. |
| `<APP>_OIDC_DISABLE_BUILT_IN_LOGIN` | optional | `true`: OIDC is the only way in; the local form is hidden **and** refused by the server. Ignored (with a warning) when OIDC is off, so it cannot lock everyone out. |

If OIDC is enabled and any of its four settings is missing, or a boolean is
malformed, `FromEnv` returns an error: exit instead of serving unprotected.

## At the IdP

Register the app as a confidential client:

- Redirect URI: `<BASE_URL>/auth/callback` (logged at startup)
- Scopes: `openid profile email`
- Token endpoint auth: `client_secret_basic`. PKCE `S256` is always used.

**Who may sign in is decided at the IdP**, not here (Authelia policy / group,
Entra "assignment required", Keycloak roles, …). Any user the IdP
authenticates for this client is let in, and the gate stores no identity: only
that this browser is authorized.

## Where state lives

`/app/data/auth/auth.json` (directory `0700`, file `0600`): the account's
username and **bcrypt hash**, and the key that signs session cookies. The
directory is the app's existing `/app/data` volume. The directory must be
writable by the app's user; `New` fails at startup with a clear message if it
is not. There is no environment variable to move it.

Creating the account rotates the signing key, so any earlier session ends.
Sessions are a signed, `HttpOnly`, `SameSite=Lax` cookie (`Secure` when the
request arrived over HTTPS, directly or via `X-Forwarded-Proto: https`) with a
sliding 7-day lifetime, and they survive restarts.

**Forgot the password?** Stop the app, delete `auth.json`, start it again
(the file is read only at startup). The first visitor then sees the setup page
again, so do it on a network you trust. There is no password-change page.

## A "Sign out" button in the app

The gate cannot decide where your UI puts a button, so the app does, and the
gate only announces itself. Include one tiny script, hide gate-only UI with one
CSS rule, and link to `/auth/logout`:

```html
<script src="/auth/client.js"></script>   <!-- in <head> -->
<style>html:not([data-oidcgate]) .only-with-gate { display: none !important }</style>

<a class="only-with-gate" href="/auth/logout">Sign out</a>
```

`/auth/client.js` sets `document.documentElement.dataset.oidcgate = "on"` and
`window.oidcgate = { signOutUrl: "/auth/logout" }`. With the gate off the file
is a 404, the attribute is never set, and everything marked `only-with-gate`
stays hidden. This works with client-side-rendered UIs, because it is CSS.

## Security notes

- Passwords: bcrypt (cost 12), 8–72 bytes (bcrypt ignores bytes past 72, so
  longer is refused instead of silently truncated), constant-time-ish
  verification even for unknown usernames.
- Local login is rate limited: 5 failures per minute, process-wide, then
  `429` until the window passes (per-IP is useless behind a proxy). OIDC is
  unaffected. The trade-off is that someone guessing can block the local form.
- Forms use a double-submit CSRF token plus a `Sec-Fetch-Site` check.
- OIDC: authorization code + PKCE (S256), `state`, `nonce`; the ID token is
  verified (signature, issuer, audience, expiry, nonce) with
  [go-oidc](https://github.com/coreos/go-oidc). Failures are logged with
  detail server-side; the user sees a generic message. Tokens and secrets are
  never logged.
- `?next=` is accepted only as a local path, and every redirect is re-checked.
- Gate pages are static, take no scripts, and send `no-store`, a strict CSP,
  `X-Frame-Options: DENY` and `Referrer-Policy: same-origin`.
- Setup is closed whenever an account exists or OIDC is configured, so nobody
  can claim an app by being first once it is set up.

This is security-critical code. It is covered by tests (run with `-race`) and
scanned with `gosec` and `govulncheck`, but it has had no independent review:
treat it accordingly.

## Limits

- One local account; no password-change or multi-user support.
- `BASE_URL` must not contain a path (no sub-path hosting).
- Each host needs its own client at the IdP.
- Not a replacement for authorization inside the app: it answers "is this
  browser signed in?", nothing finer.

## Options

For the rare case the environment isn't enough: `WithPublicPaths(...)`,
`WithSessionTTL(d)`, `WithLogger(l)`, `WithDataDir(dir)`, or build a `Config`
and call `oidcgate.New(ctx, cfg)`.

## Testing

`go test -race ./...` runs every flow against an in-process fake IdP; nothing
talks to a real provider.
