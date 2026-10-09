//go:build integration

package integration

import (
	"testing"
	"time"
)

// waitFor polls cond until it holds or the timeout passes. A convergence wait,
// not a sleep: it returns as soon as the world settles, and when it does not,
// it fails with what the world looked like (diag) instead of just "timed out".
func waitFor(t testing.TB, what string, timeout time.Duration, cond func() bool, diag func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	extra := ""
	if diag != nil {
		extra = "\n--- " + what + ": last state ---\n" + diag()
	}
	t.Fatalf("timed out after %s waiting for %s%s", timeout, what, extra)
}
