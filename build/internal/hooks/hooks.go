// Package hooks implements the Claude Code PreToolUse / PostToolUse hooks.
//
// Hooks are short-lived processes Claude Code spawns around each tool call.
// They receive a JSON envelope on stdin, are expected to write a JSON
// response to stdout, and exit. This package owns:
//
//   - The hook input/output schema (Input / DecisionEnvelope).
//   - URL/host extraction from Bash command strings, used by PreToolUse to
//     enforce per-credential destination bindings (SPEC.md §5 L4).
//   - PreToolUse policy: substitute @TOKEN_xxx@ placeholders with real values
//     iff the destination matches the placeholder's bindings.
//   - PostToolUse policy: scrub tool_response for any secret-shaped content
//     before it reaches the model.
//
// The actual binary entry points live in cmd/noleak (subcommands `hook pre`
// and `hook post`). This package is hot-path code; keep allocations tight.
package hooks

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"noleak/internal/ipc"
)

// Input is the JSON envelope Claude Code passes to a hook on stdin.
//
// Fields that are absent or that we don't read are ignored by encoding/json.
// We intentionally use json.RawMessage for ToolInput and ToolResponse so we
// can mutate them without losing tool-specific fields the schema may add.
type Input struct {
	HookEventName  string          `json:"hook_event_name"`
	SessionID      string          `json:"session_id,omitempty"`
	TranscriptPath string          `json:"transcript_path,omitempty"`
	CWD            string          `json:"cwd,omitempty"`
	ToolName       string          `json:"tool_name,omitempty"`
	ToolInput      json.RawMessage `json:"tool_input,omitempty"`
	ToolResponse   json.RawMessage `json:"tool_response,omitempty"`
}

// DecisionEnvelope is the response shape Claude Code reads from stdout.
// The exact field set varies between PreToolUse and PostToolUse but the
// shape below is the superset we emit.
type DecisionEnvelope struct {
	Decision     string      `json:"decision,omitempty"`     // "allow" | "deny" | ""
	Reason       string      `json:"reason,omitempty"`       // shown to the user
	Continue     *bool       `json:"continue,omitempty"`     // only set on hard-fail
	ToolInput    interface{} `json:"tool_input,omitempty"`   // PreToolUse mutation
	ToolResponse interface{} `json:"tool_response,omitempty"` // PostToolUse mutation
}

// Read parses a single hook input JSON document from r.
func Read(r io.Reader) (*Input, error) {
	dec := json.NewDecoder(bufio.NewReader(r))
	dec.UseNumber()
	in := new(Input)
	if err := dec.Decode(in); err != nil {
		return nil, fmt.Errorf("hooks: decode input: %w", err)
	}
	return in, nil
}

// Write emits a DecisionEnvelope to w.
func Write(w io.Writer, env *DecisionEnvelope) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(env); err != nil {
		return fmt.Errorf("hooks: encode envelope: %w", err)
	}
	return nil
}

// placeholderRe matches the noleak placeholder format used everywhere:
// `@TOKEN_<6 hex>@`.
var placeholderRe = regexp.MustCompile(`@TOKEN_[0-9a-f]{6}@`)

// findPlaceholders returns every placeholder occurrence in s, ordered by
// position. Empty if none.
func findPlaceholders(s string) []string {
	all := placeholderRe.FindAllString(s, -1)
	if len(all) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(all))
	out := all[:0]
	for _, p := range all {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// ExtractURLs scans s for absolute URLs and returns them in order. Used by
// PreToolUse to find destinations referenced in a Bash command string. The
// regex deliberately accepts http and https only; other schemes are out of
// scope for v0.
func ExtractURLs(s string) []string {
	all := urlRe.FindAllString(s, -1)
	out := make([]string, 0, len(all))
	for _, u := range all {
		out = append(out, strings.Trim(u, `"'`))
	}
	return out
}

// HostsFromCommand pulls every distinct host from URLs found in a command.
func HostsFromCommand(cmd string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0)
	for _, raw := range ExtractURLs(cmd) {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		host := u.Hostname()
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out
}

var urlRe = regexp.MustCompile(`https?://[^\s"'<>{}|\\^` + "`" + `]+`)

// runScan is a small helper that base64-encodes payload, asks the daemon
// for a redacted version, and returns the redacted bytes. autoRegister
// controls whether unknown high-confidence detections are persisted.
func runScan(client *ipc.Client, payload []byte, autoRegister bool) (redacted []byte, matches []ipc.Match, err error) {
	req := &ipc.Request{Op: ipc.OpScan, Scan: &ipc.ScanRequest{
		PayloadB64:   base64.StdEncoding.EncodeToString(payload),
		AutoRegister: autoRegister,
	}}
	resp, err := client.Call(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.Error != "" {
		return nil, nil, errors.New(resp.Error)
	}
	if resp.Scan == nil {
		return payload, nil, nil
	}
	red, err := base64.StdEncoding.DecodeString(resp.Scan.RedactedB64)
	if err != nil {
		return nil, nil, fmt.Errorf("hooks: decode redacted: %w", err)
	}
	return red, resp.Scan.Matches, nil
}

// rewriteJSONField walks the root JSON of toolInput/toolResponse, finds the
// named string field at the top level, applies fn, and returns the rewritten
// JSON bytes. Unknown structures pass through unchanged. Errors propagate.
func rewriteJSONField(raw []byte, field string, fn func(string) (string, error)) ([]byte, bool, error) {
	if !bytes.Contains(raw, []byte(field)) {
		return raw, false, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw, false, nil // not an object — leave untouched
	}
	val, ok := obj[field]
	if !ok {
		return raw, false, nil
	}
	var s string
	if err := json.Unmarshal(val, &s); err != nil {
		return raw, false, nil
	}
	out, err := fn(s)
	if err != nil {
		return nil, false, err
	}
	if out == s {
		return raw, false, nil
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, false, err
	}
	obj[field] = encoded
	rebuilt, err := json.Marshal(obj)
	if err != nil {
		return nil, false, err
	}
	return rebuilt, true, nil
}
