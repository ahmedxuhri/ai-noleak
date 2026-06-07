package hooks

import (
	"bytes"
	"context"
	"encoding/json"

	"noleak/internal/ipc"
)

// PostToolUse scrubs the tool's response payload before it enters the model's
// context. SPEC.md §5 L3.
//
// Strategy: serialize the entire tool_response JSON to bytes, run a daemon
// scan with auto_register=true, and decode the redacted bytes back into a
// generic interface for the response. This keeps the implementation tool-
// agnostic — whatever shape the result takes, any secret-bearing string in
// it gets substituted by the daemon's redactor.
func PostToolUse(ctx context.Context, in *Input, client *ipc.Client) (*DecisionEnvelope, error) {
	env := &DecisionEnvelope{}
	if in == nil || len(in.ToolResponse) == 0 {
		return env, nil
	}

	redacted, _, err := runScan(client, in.ToolResponse, true)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(redacted, in.ToolResponse) {
		return env, nil
	}

	var responseObj interface{}
	dec := newDecoder(redacted)
	if err := dec.Decode(&responseObj); err != nil {
		// If the redactor produced invalid JSON (shouldn't happen — we redact
		// in the bytes the daemon scans, the daemon doesn't reformat), leave
		// the raw redacted bytes as a string fallback.
		responseObj = string(redacted)
	}

	env.ToolResponse = responseObj
	env.Reason = "noleak: tool output scrubbed before model context"
	return env, nil
}

// newDecoder builds a json.Decoder with our preferred settings.
func newDecoder(b []byte) *json.Decoder {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec
}

// Compile-time assertion that ipc.Match isn't dropped from this file's deps,
// kept so refactors don't accidentally break the response shape.
var _ = ipc.Match{}
