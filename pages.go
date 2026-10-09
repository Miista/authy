package oidcgate

import (
	"html/template"
	"net/http"
)

// clientJS is what /auth/client.js serves. An app that wants a "Sign out"
// button includes it in <head> and hides gate-only UI with CSS:
//
//	html:not([data-oidcgate]) .only-with-gate { display: none !important }
//
// With the gate off the file is a 404, the attribute is never set, and the
// UI stays hidden.
const clientJS = `document.documentElement.dataset.oidcgate="on";window.oidcgate={signOutUrl:"/auth/logout"};` + "\n"

// pageData drives the single template behind every gate page.
type pageData struct {
	App       string
	Title     string
	Heading   string
	Error     string
	Message   string
	Next      string
	CSRF      string
	ShowForm  bool // local sign-in form
	ShowSetup bool // create-account form
	ShowOIDC  bool
	OIDCURL   string
	OIDCLabel string
	Link      string // optional trailing link, e.g. "Sign in again"
	LinkLabel string
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>{{.Title}}</title>
<style>
:root{color-scheme:dark light}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:#14151b;color:#e8e9ef}
main{width:100%;max-width:360px}
h1{font-size:20px;margin:0 0 4px}
.app{margin:0 0 20px;color:#9a9db0;font-size:14px}
p{margin:0 0 14px}
label{display:block;font-size:13px;color:#9a9db0;margin:12px 0 4px}
input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #33364a;background:#1b1d27;color:inherit;font:inherit}
input:focus-visible,.btn:focus-visible{outline:2px solid #8a7cff;outline-offset:2px}
button,.btn{display:block;width:100%;margin-top:18px;padding:11px 14px;border-radius:10px;border:1px solid #33364a;
background:#6f5cf0;color:#fff;font:inherit;font-weight:600;text-align:center;text-decoration:none;cursor:pointer}
.btn.alt{background:#1b1d27;color:#e8e9ef;margin-top:0}
.or{display:flex;align-items:center;gap:10px;margin:18px 0;color:#9a9db0;font-size:12px;text-transform:uppercase}
.or:before,.or:after{content:"";flex:1;border-top:1px solid #33364a}
.err{padding:10px 12px;border-radius:10px;background:#3a1d22;border:1px solid #6b2d36;color:#ffb4bd}
a{color:#a99cff}
@media (prefers-color-scheme:light){
body{background:#f4f5f9;color:#1b1d27}
input,.btn.alt{background:#fff;color:#1b1d27;border-color:#c9ccdb}
label,.app,.or{color:#5b5f73}.or:before,.or:after{border-color:#c9ccdb}
.err{background:#fde8ea;border-color:#f3b3ba;color:#8a1f2d}a{color:#4b3bd6}}
</style></head>
<body><main>
<h1>{{.Heading}}</h1>
<p class="app">{{.App}}</p>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
{{if .Message}}<p>{{.Message}}</p>{{end}}
{{if .ShowSetup}}
<form method="post" action="/auth/setup">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="next" value="{{.Next}}">
<label for="u">Username</label>
<input id="u" name="username" autocomplete="username" required maxlength="64" autofocus>
<label for="p">Password</label>
<input id="p" name="password" type="password" autocomplete="new-password" required minlength="8" maxlength="72">
<label for="c">Confirm password</label>
<input id="c" name="confirm" type="password" autocomplete="new-password" required minlength="8" maxlength="72">
<button type="submit">Create account</button>
</form>
{{end}}
{{if .ShowForm}}
<form method="post" action="/auth/login">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="next" value="{{.Next}}">
<label for="u">Username</label>
<input id="u" name="username" autocomplete="username" required maxlength="64" autofocus>
<label for="p">Password</label>
<input id="p" name="password" type="password" autocomplete="current-password" required maxlength="72">
<button type="submit">Sign in</button>
</form>
{{end}}
{{if .ShowOIDC}}{{if or .ShowForm .ShowSetup}}<div class="or">or</div>{{end}}
<a class="btn{{if .ShowForm}} alt{{end}}" href="{{.OIDCURL}}">{{.OIDCLabel}}</a>
{{end}}
{{if .Link}}<p><a href="{{.Link}}">{{.LinkLabel}}</a></p>{{end}}
</main></body></html>
`))

// render writes a gate page with strict headers: the pages are static, take no
// scripts, and must not be cached, framed or leak their URL as a referrer.
func (g *Gate) render(w http.ResponseWriter, status int, d pageData) {
	d.App = g.app
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	if err := pageTmpl.Execute(w, d); err != nil {
		g.log.Error("auth: rendering page", "err", err)
	}
}

// errorMessages are the user-facing texts for the ?error= codes.
var errorMessages = map[string]string{
	"access_denied": "Sign-in was not approved by the identity provider.",
	"failed":        "Sign-in failed. Please try again.",
	"unavailable":   "The identity provider is not reachable right now.",
}
