package cliroot

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"noleak/internal/hooks"
	"noleak/internal/ipc"
)

// newHookCmd returns the `noleak hook ...` subcommand tree. Sub-subcommands
// `pre` and `post` are wired into the Claude Code hook system via
// settings.json: their stdin/stdout matches the documented hook protocol.
func newHookCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "hook",
		Short: "PreToolUse / PostToolUse hook entry points (called by Claude Code)",
	}
	c.AddCommand(newHookPreCmd())
	c.AddCommand(newHookPostCmd())
	return c
}

func newHookPreCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "pre",
		Short: "PreToolUse: binding-aware placeholder substitution",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHookPre()
		},
	}
	return c
}

func newHookPostCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "post",
		Short: "PostToolUse: scrub tool result before it enters model context",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHookPost()
		},
	}
	return c
}

func runHookPre() error {
	in, err := hooks.Read(os.Stdin)
	if err != nil {
		return err
	}
	client := ipc.NewClient(defaultSocketPath())
	env, err := hooks.PreToolUse(context.Background(), in, client)
	if err != nil {
		return failOpen(err)
	}
	return hooks.Write(os.Stdout, env)
}

func runHookPost() error {
	in, err := hooks.Read(os.Stdin)
	if err != nil {
		return err
	}
	client := ipc.NewClient(defaultSocketPath())
	env, err := hooks.PostToolUse(context.Background(), in, client)
	if err != nil {
		return failOpen(err)
	}
	return hooks.Write(os.Stdout, env)
}

// failOpen prints the error to stderr and emits an empty envelope. We do NOT
// exit non-zero for transient daemon issues — that would block legitimate
// tool calls every time noleakd restarts. Hard errors (malformed input)
// still return non-zero from the caller.
func failOpen(err error) error {
	fmt.Fprintf(os.Stderr, "noleak hook: %v (passing through)\n", err)
	return hooks.Write(os.Stdout, &hooks.DecisionEnvelope{})
}

func defaultSocketPath() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".noleak", "sock")
	}
	return "/tmp/noleak.sock"
}
