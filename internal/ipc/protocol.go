// Package ipc defines the wire protocol between noleakd and its clients
// (PTY wrapper, proxy, hooks, CLI). See SPEC.md §4 IPC.
//
// Transport: Unix domain socket. Authentication: SO_PEERCRED UID equality
// against the daemon's own UID. Framing: 4-byte big-endian length prefix
// followed by a single JSON object.
package ipc

// Op names every operation the daemon serves. New operations append; never
// renumber. Daemon and clients share this constant set.
const (
	OpScan     = "scan"
	OpResolve  = "resolve"
	OpRegister = "register"
	OpBind     = "bind"
	OpUnbind   = "unbind"
	OpList     = "list"
	OpRotate   = "rotate"
	OpDelete   = "delete"
	OpHealth   = "health"
)

// Request is the envelope. Op selects which Payload field is meaningful.
type Request struct {
	Op       string           `json:"op"`
	Scan     *ScanRequest     `json:"scan,omitempty"`
	Resolve  *ResolveRequest  `json:"resolve,omitempty"`
	Register *RegisterRequest `json:"register,omitempty"`
	Bind     *BindRequest     `json:"bind,omitempty"`
	Unbind   *BindRequest     `json:"unbind,omitempty"`
	Rotate   *RotateRequest   `json:"rotate,omitempty"`
	Delete   *DeleteRequest   `json:"delete,omitempty"`
}

// Response is uniform across ops. Exactly one of Error or one of the
// op-specific result fields is populated.
type Response struct {
	Error    string            `json:"error,omitempty"`
	Scan     *ScanResponse     `json:"scan,omitempty"`
	Resolve  *ResolveResponse  `json:"resolve,omitempty"`
	Register *RegisterResponse `json:"register,omitempty"`
	List     *ListResponse     `json:"list,omitempty"`
	Health   *HealthResponse   `json:"health,omitempty"`
	OK       bool              `json:"ok,omitempty"`
}

// ScanRequest scans bytes and (when AutoRegister is true) inserts new high-
// confidence detections into the vault before returning.
type ScanRequest struct {
	PayloadB64   string `json:"payload_b64"`
	AutoRegister bool   `json:"auto_register"`
}

// Match mirrors detect.Match on the wire.
type Match struct {
	Start       int     `json:"start"`
	End         int     `json:"end"`
	Kind        string  `json:"kind"`
	Source      string  `json:"source"`
	Confidence  float64 `json:"confidence"`
	Placeholder string  `json:"placeholder,omitempty"` // populated when matched against vault or auto-registered
}

// ScanResponse returns the matches and (optionally) the redacted payload
// with placeholders substituted in place of detected secrets.
type ScanResponse struct {
	Matches     []Match `json:"matches"`
	RedactedB64 string  `json:"redacted_b64,omitempty"`
}

// ResolveRequest asks whether Placeholder may be substituted with its real
// value when the destination is DestHost. The daemon enforces bindings.
type ResolveRequest struct {
	Placeholder string `json:"placeholder"`
	DestHost    string `json:"dest_host"`
}

// ResolveResponse: Value populated only on a binding match; empty otherwise.
type ResolveResponse struct {
	Value string `json:"value,omitempty"`
}

// RegisterRequest manually inserts a value with optional bindings.
type RegisterRequest struct {
	Value    string   `json:"value"`
	Kind     string   `json:"kind"`
	Source   string   `json:"source,omitempty"`
	Bindings []string `json:"bindings,omitempty"`
}

// RegisterResponse returns the placeholder assigned to Value.
type RegisterResponse struct {
	Placeholder string `json:"placeholder"`
}

// BindRequest binds (or unbinds) a placeholder to one or more host patterns.
type BindRequest struct {
	Placeholder string   `json:"placeholder"`
	Hosts       []string `json:"hosts"`
}

// RotateRequest atomically replaces the value behind Placeholder.
type RotateRequest struct {
	Placeholder string `json:"placeholder"`
	NewValue    string `json:"new_value"`
}

// DeleteRequest removes an entry from the vault.
type DeleteRequest struct {
	Placeholder string `json:"placeholder"`
}

// ListResponse describes the current vault contents (placeholders + metadata).
type ListResponse struct {
	Entries []ListEntry `json:"entries"`
}

// ListEntry never includes a Value. Forensic listings are a separate op
// reserved for the CLI under explicit human gate (see SPEC.md §7).
type ListEntry struct {
	Placeholder  string   `json:"placeholder"`
	Kind         string   `json:"kind"`
	Source       string   `json:"source,omitempty"`
	Bindings     []string `json:"bindings,omitempty"`
	Status       string   `json:"status"`
	RegisteredAt string   `json:"registered_at"`
	Uses         int      `json:"uses"`
}

// HealthResponse reports daemon vitals. Used by systemd / `noleak status`.
type HealthResponse struct {
	Version       string `json:"version"`
	Unlocked      bool   `json:"unlocked"`
	VaultEntries  int    `json:"vault_entries"`
	PendingReview int    `json:"pending_review"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}
