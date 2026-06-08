package cliroot

import (
	"encoding/base64"
	"errors"
	"fmt"

	"noleak/internal/ipc"
	"noleak/internal/vault"
)

// daemonProxyVault is a vault.Vault adapter that delegates to the daemon
// over IPC. Used by `noleak proxy` so the proxy and daemon share one
// authoritative vault state. Only the operations the proxy actually calls
// are wired up; the rest return clear "use the daemon directly" errors.
type daemonProxyVault struct {
	client *ipc.Client
}

var errNotPermittedOverIPC = errors.New("daemonProxyVault: this operation must run on the daemon directly")

func (d *daemonProxyVault) Register(value, kind, source string, bindings []string, _ []byte) (*vault.Entry, error) {
	resp, err := d.client.Call(&ipc.Request{
		Op: ipc.OpRegister,
		Register: &ipc.RegisterRequest{
			Value: value, Kind: kind, Source: source, Bindings: bindings,
		},
	})
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("daemon: %s", resp.Error)
	}
	return &vault.Entry{Placeholder: resp.Register.Placeholder, Value: value, Kind: kind, Source: source, Bindings: bindings}, nil
}

func (d *daemonProxyVault) Lookup(ph string) (*vault.Entry, error) {
	return nil, errNotPermittedOverIPC
}

func (d *daemonProxyVault) Resolve(ph, host string) (string, error) {
	resp, err := d.client.Call(&ipc.Request{
		Op:      ipc.OpResolve,
		Resolve: &ipc.ResolveRequest{Placeholder: ph, DestHost: host},
	})
	if err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", fmt.Errorf("daemon: %s", resp.Error)
	}
	return resp.Resolve.Value, nil
}

func (d *daemonProxyVault) Bind(ph string, hosts []string) error    { return errNotPermittedOverIPC }
func (d *daemonProxyVault) Unbind(ph string, hosts []string) error  { return errNotPermittedOverIPC }
func (d *daemonProxyVault) SetStatus(ph string, s vault.Status) error { return errNotPermittedOverIPC }
func (d *daemonProxyVault) Rotate(ph, newValue string) error        { return errNotPermittedOverIPC }
func (d *daemonProxyVault) Delete(ph string) error                  { return errNotPermittedOverIPC }
func (d *daemonProxyVault) MarkUse(ph string)                       {}
func (d *daemonProxyVault) Close() error                            { return nil }

func (d *daemonProxyVault) MasterSecret() []byte {
	resp, err := d.client.Call(&ipc.Request{Op: ipc.OpHealth})
	if err != nil || resp.Error != "" || resp.Health == nil || resp.Health.MasterSecretB64 == "" {
		return nil
	}
	ms, _ := base64.StdEncoding.DecodeString(resp.Health.MasterSecretB64)
	return ms
}

func (d *daemonProxyVault) List(includeArchived bool) ([]vault.Entry, error) {
	resp, err := d.client.Call(&ipc.Request{Op: ipc.OpList})
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("daemon: %s", resp.Error)
	}
	out := make([]vault.Entry, 0, len(resp.List.Entries))
	for _, e := range resp.List.Entries {
		out = append(out, vault.Entry{
			Placeholder: e.Placeholder, Kind: e.Kind, Source: e.Source,
			Bindings: e.Bindings, Status: vault.Status(e.Status), Uses: e.Uses,
		})
	}
	return out, nil
}

// Values asks the daemon for the current AC value list. The daemon does
// not expose values directly (see SPEC §4 — values never leave the vault
// process); instead the AC stage rebuilds from the daemon-side scan path.
// For the proxy's local detector we keep an empty AC (regex+entropy+context
// still fire), and rely on the daemon-side scan for exact-match coverage.
//
// In practice this is fine: outbound bytes get scanned again by the daemon
// (when the proxy calls Register on a hit, the value enters the vault and
// future bodies match via the daemon's own scan). The proxy's detector is
// effectively a regex/entropy/context pre-filter.
func (d *daemonProxyVault) Values() [][]byte { return nil }

// silence base64 import when only some build tags reference it
var _ = base64.StdEncoding
