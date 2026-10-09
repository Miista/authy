//go:build integration

package integration

import (
	"fmt"
	"os"
	"testing"
)

// TestMain builds the images once for the package. No *testing.T here, so a
// setup failure is an exit rather than a test failure: nothing can run
// without it.
func TestMain(m *testing.M) {
	if err := Setup(); err != nil {
		fmt.Fprintf(os.Stderr, "integration: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	Teardown()
	os.Exit(code)
}
