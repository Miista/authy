package authy

import (
	"html/template"
	"net/http"
)

// clientJS is what /auth/client.js serves. An app that wants a "Sign out"
// button includes it in <head> and hides gate-only UI with CSS:
//
//	html:not([data-authy]) .only-with-gate { display: none !important }
//
// With the gate off the file is a 404, the attribute is never set, and the
// UI stays hidden.
const clientJS = `document.documentElement.dataset.authy="on";window.authy={signOutUrl:"/auth/logout"};` + "\n"

// pageData drives the single template behind every gate page.
type pageData struct {
	App       string
	Title     string
	Heading   string
	Error     string
	Message   string
	Entries   []pageEntry // one button per sign-in method
	Link      string      // optional trailing link, e.g. "Sign in again"
	LinkLabel string
}

type pageEntry struct {
	Label string
	URL   string
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
.btn:focus-visible{outline:2px solid #8a7cff;outline-offset:2px}
.btn{display:block;width:100%;margin-top:18px;padding:11px 14px;border-radius:10px;border:1px solid #33364a;
background:#6f5cf0;color:#fff;font:inherit;font-weight:600;text-align:center;text-decoration:none;cursor:pointer}
.err{padding:10px 12px;border-radius:10px;background:#3a1d22;border:1px solid #6b2d36;color:#ffb4bd}
a{color:#a99cff}
@media (prefers-color-scheme:light){
body{background:#f4f5f9;color:#1b1d27}
.app{color:#5b5f73}
.err{background:#fde8ea;border-color:#f3b3ba;color:#8a1f2d}a{color:#4b3bd6}}
</style></head>
<body><main>
<h1>{{.Heading}}</h1>
<p class="app">{{.App}}</p>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
{{if .Message}}<p>{{.Message}}</p>{{end}}
{{range .Entries}}
<a class="btn" href="{{.URL}}">{{.Label}}</a>
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
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
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
