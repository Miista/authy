// Package testhook holds knobs that only test binaries turn. Production code
// reads them; nothing outside a TestMain writes them.
package testhook

// BcryptCost is the cost the local account hashes with. Tests across packages
// lower it to bcrypt.MinCost so suites don't pay production-strength hashing.
var BcryptCost = 12
