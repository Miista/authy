// Command subject is the smallest possible app behind oidcgate: the two lines
// the README promises, and a page to protect. The integration suite builds it
// into a scratch image and runs it as a container, so the gate is exercised
// the way an app ships it -- as a non-root process in a container with a
// mounted data directory -- not just in-process.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Miista/oidcgate"
)

func main() {
	// The app is called "demo", so its settings are DEMO_AUTH_* and DEMO_OIDC_*.
	gate, err := oidcgate.FromEnv(context.Background(), "demo")
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid auth configuration:", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The script tag is the whole contract an app needs for a Sign out button.
		_, _ = io.WriteString(w, `<!doctype html><script src="/auth/client.js"></script><p>hello demo</p>`)
	})

	if err := http.ListenAndServe(":8080", gate.Wrap(mux)); err != nil { // #nosec G114 -- test subject
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
