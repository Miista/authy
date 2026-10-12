//go:build integration

// Package integration runs authy the way an app ships it: inside a
// container, as a non-root process, with a mounted data directory, next to a
// real identity-provider container over a real docker network.
//
// The world a test needs is a compose file under hack/fixtures/<suite>/<name>,
// readable on its own terms. A test copies one into the testbed, brings it
// up, drives it over HTTP the way a browser would, and asserts on what
// happened. Nothing upstream is contacted: the subject app and the fake IdP
// are built from this repository's source into scratch images, so the suite
// works offline.
//
// The in-process tests in the package root are fast and cover the logic. What
// only a container can show lives here: file modes and ownership in a real
// volume, persistence across a restart, refusing to start, and an IdP that is
// not there yet.
package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	subjectImage = "authy-subject:integration"
	idpImage     = "authy-fakeidp:integration"

	// project is the compose project name for every scenario. Fixed, so a
	// scenario can always be found again and removed -- a random one is how
	// containers survive a killed run.
	project = "authy-it"

	// label marks everything the suite builds, so a sweep removes exactly ours.
	label = "authy-test"
)

func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("finding the repository root: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// docker runs one docker command and returns its trimmed combined output.
func docker(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// daemonArch is the architecture the docker daemon runs containers as, which
// on a Mac is not necessarily what this process is.
func daemonArch() string {
	out, err := docker("info", "--format", "{{.Architecture}}")
	if err == nil {
		switch strings.TrimSpace(out) {
		case "aarch64", "arm64":
			return "arm64"
		case "x86_64", "amd64":
			return "amd64"
		}
	}
	return runtime.GOARCH
}

// buildHelper compiles one of this repository's helper programs for the
// daemon and wraps it in a FROM scratch image: nothing is pulled.
func buildHelper(root, pkg, image, arch string) error {
	dir, err := os.MkdirTemp("", "authy-it-build")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	bin := filepath.Join(dir, "app")
	build := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", bin, pkg)
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %w\n%s", pkg, err, out)
	}
	// Not at /app: that is where the subject's data volume is mounted, and a
	// mount point cannot be created inside a file.
	dockerfile := "FROM scratch\nCOPY app /bin/helper\nENTRYPOINT [\"/bin/helper\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		return err
	}
	_, err = docker("build", "-q", "--label", label+"=1", "-t", image, dir)
	return err
}

// sweep removes whatever a previous (possibly killed) run left running.
func sweep() {
	_, _ = docker("compose", "-p", project, "down", "-v", "--remove-orphans", "-t", "1")
}

// Setup builds the images every scenario uses.
func Setup() error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	if _, err := docker("version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("the integration suite needs a running docker daemon: %w", err)
	}
	sweep()
	// Testbeds a killed run left behind (a clean run removes its own).
	if old, _ := filepath.Glob(filepath.Join(root, "testbed-*")); len(old) > 0 {
		for _, d := range old {
			_ = os.RemoveAll(d)
		}
	}
	arch := daemonArch()
	if err := buildHelper(root, "./test/integration/subject", subjectImage, arch); err != nil {
		return fmt.Errorf("building %s: %w", subjectImage, err)
	}
	if err := buildHelper(root, "./test/integration/fakeidp", idpImage, arch); err != nil {
		return fmt.Errorf("building %s: %w", idpImage, err)
	}
	return nil
}

// Teardown removes what the scenarios started. The images stay: rebuilt next
// run, and removing them would discard the layer cache that makes a rerun quick.
func Teardown() { sweep() }
