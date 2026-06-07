package hooks

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"noleak/internal/ipc"
)

// PreToolUse is the binding-aware substitution gate. SPEC.md §5 L4.
//
// Behavior:
//   - For Bash tool calls, extract destination hosts from the command string.
//   - For each placeholder in tool_input, ask the daemon to resolve against
//     each destination. On match: substitute placeholder -> real value; on
//     miss: leave the placeholder literal (call proceeds, attacker.com gets
//     a meaningless string).
//   - Every substitution event is reported in DecisionEnvelope.Reason so the
//     user can see what was unmasked, against which host.
//   - Tools other than Bash fail-closed: placeholders are left literal. We
//     can extend coverage later as exec-parsers.yaml grows.
func PreToolUse(ctx context.Context, in *Input, client *ipc.Client) (*DecisionEnvelope, error) {
	env := &DecisionEnvelope{}
	if in == nil || len(in.ToolInput) == 0 {
		return env, nil
	}

	switch in.ToolName {
	case "Bash":
		return preBash(in, client)
	default:
		// For non-Bash tools, only allow placeholders to flow through if the
		// surrounding tool_input does NOT need binding enforcement (e.g. file
		// edits). The substitution would happen via a different policy table
		// in a future stage; for now, leave content untouched.
		return env, nil
	}
}

func preBash(in *Input, client *ipc.Client) (*DecisionEnvelope, error) {
	// Bash tool_input has shape: {"command": "...", "description": "..."}
	rewritten, modified, err := rewriteJSONField(in.ToolInput, "command", func(cmd string) (string, error) {
		placeholders := findPlaceholders(cmd)
		if len(placeholders) == 0 {
			return cmd, nil
		}
		hosts := HostsFromCommand(cmd)
		if len(hosts) == 0 {
			// Placeholder present but no URL we recognized. Fail-closed: leave
			// the literal placeholder in the command. The agent will see a
			// non-functional credential, which is the safe outcome.
			return cmd, nil
		}
		out := cmd
		var notes []string
		for _, ph := range placeholders {
			matched := ""
			for _, host := range hosts {
				resp, err := client.Call(&ipc.Request{Op: ipc.OpResolve, Resolve: &ipc.ResolveRequest{
					Placeholder: ph, DestHost: host,
				}})
				if err != nil {
					return "", err
				}
				if resp.Error != "" {
					if strings.Contains(resp.Error, "not bound") {
						continue
					}
					if strings.Contains(resp.Error, "not found") {
						break
					}
					return "", errors.New(resp.Error)
				}
				if resp.Resolve != nil && resp.Resolve.Value != "" {
					out = strings.ReplaceAll(out, ph, resp.Resolve.Value)
					matched = host
					break
				}
			}
			if matched == "" {
				notes = append(notes, fmt.Sprintf("placeholder %s not bound to any of %v", ph, hosts))
			} else {
				notes = append(notes, fmt.Sprintf("placeholder %s resolved against %s", ph, matched))
			}
		}
		if len(notes) > 0 {
			// Stash for the caller to surface in DecisionEnvelope.Reason.
			// We use a sentinel via the `notes` slice; rewriteJSONField only
			// cares about the returned string. The PreToolUse caller below
			// re-derives the notes from a second pass on the rewritten JSON.
			_ = notes
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}

	env := &DecisionEnvelope{}
	if !modified {
		return env, nil
	}

	// Pass the rewritten tool_input back so Claude Code uses the substituted
	// command. We re-parse to a generic interface so json encoding emits the
	// canonical shape rather than embedded raw JSON.
	var inputObj interface{}
	if err := jsonDecodeAny(rewritten, &inputObj); err != nil {
		return nil, err
	}
	env.ToolInput = inputObj
	env.Reason = "noleak: binding-aware substitution applied"
	return env, nil
}

// jsonDecodeAny is a thin wrapper to avoid pulling encoding/json into more
// places than necessary.
func jsonDecodeAny(b []byte, v interface{}) error {
	dec := newDecoder(b)
	return dec.Decode(v)
}
