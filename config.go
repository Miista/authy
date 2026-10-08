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

// Config is the full configuration of a Gate. Most callers never build one:
// FromEnv fills it from <APP>_OIDC_* environment variables.
type Config struct {
	// App is the application name. It namespaces the cookies, so several
	// apps on one host (different ports) never read each other's sessions.
	App string

	Issuer       string // IdP issuer URL, e.g. https://auth.example.com
	ClientID     string
	ClientSecret string

	// BaseURL is the external URL of this app, e.g. https://myapp.example.com.
	// The redirect URI registered at the IdP is BaseURL + "/auth/callback".
	// It must not contain a path.
	BaseURL string

	// SessionSecret signs the session cookies (min 16 chars). Empty means a
	// random key per process start: sessions then end on every restart.
	SessionSecret string

	// SessionTTL is the sliding session lifetime. Default 7 days.
	SessionTTL time.Duration

	// PublicPaths bypass authentication. An entry ending in "/" is a prefix;
	// anything else is an exact match. Default: /healthz.
	PublicPaths []string

	// Scopes requested from the IdP. Default: openid profile email.
	Scopes []string

	Logger *slog.Logger
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

// FromEnv builds a Gate from <APP>_OIDC_* environment variables, where <APP>
// is app upper-cased with non-alphanumerics replaced by "_":
//
//	<APP>_OIDC_ENABLED         true to turn OIDC on (anything else: off)
//	<APP>_OIDC_ISSUER          required when enabled
//	<APP>_OIDC_CLIENT_ID       required when enabled
//	<APP>_OIDC_CLIENT_SECRET   required when enabled
//	<APP>_OIDC_BASE_URL        required when enabled
//	<APP>_OIDC_SESSION_SECRET  optional
//	<APP>_OIDC_PUBLIC_PATHS    optional, comma-separated, added to /healthz
//
// When OIDC is not enabled it returns (nil, nil), and (*Gate)(nil).Wrap is a
// no-op, so the same two lines work with auth on or off. When it is enabled
// but misconfigured, or the issuer is unreachable, it returns an error: the
// caller should refuse to start rather than serve unauthenticated.
func FromEnv(ctx context.Context, app string, opts ...Option) (*Gate, error) {
	p := envPrefix(app) + "_OIDC_"

	if raw := strings.TrimSpace(os.Getenv(p + "ENABLED")); raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("oidc: %sENABLED=%q is not a boolean", p, raw)
		}
		if !enabled {
			return nil, nil
		}
	} else {
		return nil, nil
	}

	cfg := Config{
		App:           app,
		Issuer:        strings.TrimSpace(os.Getenv(p + "ISSUER")),
		ClientID:      strings.TrimSpace(os.Getenv(p + "CLIENT_ID")),
		ClientSecret:  os.Getenv(p + "CLIENT_SECRET"),
		BaseURL:       strings.TrimSpace(os.Getenv(p + "BASE_URL")),
		SessionSecret: os.Getenv(p + "SESSION_SECRET"),
	}
	for _, path := range strings.Split(os.Getenv(p+"PUBLIC_PATHS"), ",") {
		if path = strings.TrimSpace(path); path != "" {
			cfg.PublicPaths = append(cfg.PublicPaths, path)
		}
	}
	for _, o := range opts {
		o(&cfg)
	}

	var missing []string
	for _, v := range []struct{ name, val string }{
		{"ISSUER", cfg.Issuer},
		{"CLIENT_ID", cfg.ClientID},
		{"CLIENT_SECRET", cfg.ClientSecret},
		{"BASE_URL", cfg.BaseURL},
	} {
		if v.val == "" {
			missing = append(missing, p+v.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("oidc: enabled but missing %s", strings.Join(missing, ", "))
	}
	return New(ctx, cfg)
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
