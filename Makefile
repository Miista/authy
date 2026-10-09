.PHONY: test test-unit test-integration scan

# test-unit needs nothing but Go. test-integration needs docker: it builds a
# tiny subject app and a fake identity provider from this repository into
# scratch images and runs each scenario under hack/fixtures as its own compose
# stack. Nothing upstream is contacted, so it works offline.
#
# Only test-integration passes -count=1. Go caches a passing result and replays
# it when nothing it can see has changed, which is right for pure code and wrong
# here: these depend on a daemon, on images and on containers, none of which the
# cache knows about.
test: test-unit test-integration

test-unit:
	go test -race -shuffle=on ./...

# -p 1 keeps packages sequential: every scenario shares one testbed and one
# compose project name. -shuffle=on prints the seed, and -shuffle=<seed> replays
# a failure exactly.
test-integration:
	go test -tags integration -count=1 -p 1 -shuffle=on ./test/...

# The security checks to run before tagging a release. Pin the Go toolchain to
# the latest patch release first (govulncheck reports standard-library issues
# of whatever Go built the binary).
scan:
	go vet ./...
	go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
