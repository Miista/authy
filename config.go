package oidcgate

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// defaultDataDir is where the account and the session-signing key live. Every
// app in this stack already mounts /app/data, so the gate needs no extra volume.
const defaultDataDir = "/app/data/auth"

// Config is the full configuration of a Gate. Most callers never build one:
// FromEnv fills it from <APP>_* environment variables.
type Config struct {
	// App is the application name. It namespaces the cookies, so several
	// apps on one host (different ports) never read each other's sessions.
	App string

	// OIDC turns on login through an OpenID Connect provider. Nil means the
	// gate offers only the local account.
	OIDC *OIDCConfig

	// DisableBuiltInLogin hides and refuses the local login, so OIDC is the
	// only way in. It has no effect (and logs a warning) without OIDC, so a
	// stray flag can never lock everyone out.
	DisableBuiltInLogin bool

	// DataDir holds auth.json (account + signing key). Default /app/data/auth.
	DataDir string

	// SessionTTL is the sliding session lifetime. Default 7 days.
	SessionTTL time.Duration

	// PublicPaths bypass authentication. An entry ending in "/" is a prefix;
	// anything else is an exact match. Default: /healthz.
	PublicPaths []string

	Logger *slog.Logger

	retryBase time.Duration // first OIDC discovery retry delay; tests shorten it
}

// OIDCConfig configures the OpenID Connect provider.
type OIDCConfig struct {
	Issuer       string // IdP issuer URL, e.g. https://auth.example.com
	ClientID     string
	ClientSecret string

	// BaseURL is the external URL of this app, e.g. https://myapp.example.com.
	// The redirect URI registered at the IdP is BaseURL + "/auth/callback".
	// It must not contain a path.
	BaseURL string

	// Scopes requested from the IdP. Default: openid profile email.
	Scopes []string
}

// Option adjusts the Config that FromEnv builds, for the rare app that
// needs more than the environment offers.
type Option func(*Config)

// WithPublicPaths adds paths that bypass authentication (see Config.PublicPaths).
func WithPublicPaths(paths ...string) Option {
	return func(c *Config) { c.PublicPaths = append(c.PublicPaths, paths...) }
}

// WithSessionTTL overrides the session lifetime.
func WithSessionTTL(d time.Duration) Option { return func(c *Config) { c.SessionTTL = d } }

// WithLogger sets the logger. Default: slog.Default().
func WithLogger(l *slog.Logger) Option { return func(c *Config) { c.Logger = l } }

// WithDataDir overrides where the account and signing key are stored.
func WithDataDir(dir string) Option { return func(c *Config) { c.DataDir = dir } }

// FromEnv builds a Gate for an app from <APP>_* environment variables, where
// <APP> is app upper-cased with non-alphanumerics replaced by "_".
//
// The gate is ON by default: the first visitor creates a local account, and
// every later visit needs it. Optional OIDC login sits alongside:
//
//	<APP>_AUTH_DISABLED               true: no gate at all, FromEnv returns nil
//	                                  (for apps deliberately behind forward auth)
//	<APP>_AUTH_PUBLIC_PATHS           comma-separated paths that skip auth, added to /healthz
//	<APP>_OIDC_ENABLED                true turns OIDC login on
//	<APP>_OIDC_ISSUER                 required when OIDC is enabled
//	<APP>_OIDC_CLIENT_ID              required when OIDC is enabled
//	<APP>_OIDC_CLIENT_SECRET          required when OIDC is enabled
//	<APP>_OIDC_BASE_URL               required when OIDC is enabled
//	<APP>_OIDC_DISABLE_BUILT_IN_LOGIN true: OIDC is the only way in (needs OIDC enabled)
//
// (*Gate)(nil).Wrap is a no-op, so the same two lines work with the gate on
// or off. Malformed or incomplete settings are an error: the caller should
// refuse to start rather than serve unprotected. An OIDC provider that is
// merely unreachable is not an error; the gate retries in the background and
// the local login keeps working meanwhile.
func FromEnv(ctx context.Context, app string, opts ...Option) (*Gate, error) {
	p := envPrefix(app) + "_"

	off, err := envBool(p + "AUTH_DISABLED")
	if err != nil {
		return nil, err
	}
	if off {
		slog.Warn("auth: disabled; the app is not protected by oidcgate", "reason", p+"AUTH_DISABLED")
		return nil, nil
	}

	cfg := Config{App: app}

	oidcOn, err := envBool(p + "OIDC_ENABLED")
	if err != nil {
		return nil, err
	}
	if oidcOn {
		o := &OIDCConfig{
			Issuer:       strings.TrimSpace(os.Getenv(p + "OIDC_ISSUER")),
			ClientID:     strings.TrimSpace(os.Getenv(p + "OIDC_CLIENT_ID")),
			ClientSecret: os.Getenv(p + "OIDC_CLIENT_SECRET"),
			BaseURL:      strings.TrimSpace(os.Getenv(p + "OIDC_BASE_URL")),
		}
		var missing []string
		for _, v := range []struct{ name, val string }{
			{"ISSUER", o.Issuer}, {"CLIENT_ID", o.ClientID}, {"CLIENT_SECRET", o.ClientSecret}, {"BASE_URL", o.BaseURL},
		} {
			if v.val == "" {
				missing = append(missing, p+"OIDC_"+v.name)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("auth: OIDC enabled but missing %s", strings.Join(missing, ", "))
		}
		cfg.OIDC = o
	}

	if cfg.DisableBuiltInLogin, err = envBool(p + "OIDC_DISABLE_BUILT_IN_LOGIN"); err != nil {
		return nil, err
	}
	for _, path := range strings.Split(os.Getenv(p+"AUTH_PUBLIC_PATHS"), ",") {
		if path = strings.TrimSpace(path); path != "" {
			cfg.PublicPaths = append(cfg.PublicPaths, path)
		}
	}
	for _, o := range opts {
		o(&cfg)
	}
	return New(ctx, cfg)
}

// envBool reads a boolean variable; unset or empty is false.
func envBool(name string) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("auth: %s=%q is not a boolean", name, raw)
	}
	return v, nil
}

func envPrefix(app string) string {
	b := []byte(strings.ToUpper(app))
	for i, c := range b {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			b[i] = '_'
		}
	}
	return string(b)
}
