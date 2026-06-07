// Package config loads ~/.noleak/config.yaml. Every overridable behavior in
// noleak lives here; defaults match SPEC.md. The config file is missing on a
// fresh install — Load returns Defaults() in that case.
//
// VPS-readiness: this package contains no host-specific assumptions. Paths
// are home-relative, ports are configurable, watch lists are explicit.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the top-level shape. Fields with `omitempty` use Defaults().
type Config struct {
	// Daemon
	SocketPath string `yaml:"socket_path,omitempty"`
	VaultPath  string `yaml:"vault_path,omitempty"`

	// Master-key sourcing. One of: "passphrase" (default for VPS),
	// "libsecret" (desktop), "kernel-keyring" (headless Linux opt-in).
	MasterKeyMode string `yaml:"master_key_mode,omitempty"`

	// Proxy
	ProxyListen   string `yaml:"proxy_listen,omitempty"`   // default 127.0.0.1:9999
	ProxyUpstream string `yaml:"proxy_upstream,omitempty"` // required for proxy use; e.g. https://api.anthropic.com or https://apistore.space

	// Detector
	AutoRegisterMinConf float64 `yaml:"auto_register_min_conf,omitempty"`

	// Bootstrap
	BootstrapRoots    []string `yaml:"bootstrap_roots,omitempty"`    // override DefaultRoots
	BootstrapExcludes []string `yaml:"bootstrap_excludes,omitempty"` // ADDED to DefaultExcludes

	// Watcher
	Watch []WatchRule `yaml:"watch,omitempty"`
}

// WatchRule mirrors watch.Rule but with a string action so it serializes cleanly.
type WatchRule struct {
	Path   string `yaml:"path"`
	Action string `yaml:"action"` // "purge" or "redact"
}

// Defaults returns the zero-config Config. SocketPath/VaultPath are filled
// from $HOME at call time; everything else is hardcoded.
func Defaults(home string) Config {
	return Config{
		SocketPath:          filepath.Join(home, ".noleak", "sock"),
		VaultPath:           filepath.Join(home, ".noleak", "vault.bin"),
		MasterKeyMode:       "passphrase",
		ProxyListen:         "127.0.0.1:9999",
		ProxyUpstream:       "", // user must set this if they want the proxy
		AutoRegisterMinConf: 0.85,
	}
}

// Path returns the standard config file path under $HOME.
func Path(home string) string {
	return filepath.Join(home, ".noleak", "config.yaml")
}

// Load reads the file at Path(home) if it exists and merges with Defaults.
// Returns Defaults if the file is missing.
func Load(home string) (Config, error) {
	def := Defaults(home)
	data, err := os.ReadFile(Path(home))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return def, nil
		}
		return def, fmt.Errorf("config: read: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return def, fmt.Errorf("config: parse: %w", err)
	}
	return merge(def, c), nil
}

// Save writes the config file with mode 0600.
func Save(home string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(Path(home)), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(Path(home), data, 0o600)
}

// merge fills empty fields of `c` from `def`. Slices are NOT merged — a
// non-nil user slice replaces the default entirely (so users can opt out of
// default watch rules by listing an empty `watch: []`). BootstrapExcludes is
// the documented exception (additive).
func merge(def, c Config) Config {
	if c.SocketPath == "" {
		c.SocketPath = def.SocketPath
	}
	if c.VaultPath == "" {
		c.VaultPath = def.VaultPath
	}
	if c.MasterKeyMode == "" {
		c.MasterKeyMode = def.MasterKeyMode
	}
	if c.ProxyListen == "" {
		c.ProxyListen = def.ProxyListen
	}
	if c.AutoRegisterMinConf == 0 {
		c.AutoRegisterMinConf = def.AutoRegisterMinConf
	}
	return c
}

// Validate checks for obviously-wrong configurations. Called by every
// subcommand that consumes the config.
func Validate(c Config) error {
	switch c.MasterKeyMode {
	case "passphrase", "libsecret", "kernel-keyring":
	default:
		return fmt.Errorf("config: master_key_mode must be passphrase|libsecret|kernel-keyring, got %q", c.MasterKeyMode)
	}
	for _, w := range c.Watch {
		if w.Action != "purge" && w.Action != "redact" {
			return fmt.Errorf("config: watch[%q].action must be purge|redact, got %q", w.Path, w.Action)
		}
	}
	return nil
}
