package cliroot

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"noleak/internal/ipc"
)

func defaultClient() *ipc.Client {
	return ipc.NewClient(defaultSocketPath())
}

func newInitCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "init",
		Short: "First-time install: run bootstrap harvest into the daemon vault",
		Long:  "Walks scope-3 paths and ingests every detection into the vault as pending_review.",
		RunE: func(cmd *cobra.Command, args []string) error {
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			roots, _ := cmd.Flags().GetStringSlice("root")
			return runInit(dryRun, roots)
		},
	}
	c.Flags().Bool("dry-run", false, "scan and report but do not auto-register")
	c.Flags().StringSlice("root", nil, "override default scope; repeat for multiple roots")
	return c
}

func newAddCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "add <kind>",
		Short: "Manually register a secret (read from stdin or --from-file)",
		Long:  "Reads value bytes from stdin (default) or --from-file, sends to the daemon, prints the placeholder. Bind one or more --bind hosts to enable PreToolUse substitution against those destinations.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind := args[0]
			fromFile, _ := cmd.Flags().GetString("from-file")
			binds, _ := cmd.Flags().GetStringSlice("bind")

			var raw []byte
			var err error
			if fromFile != "" {
				raw, err = os.ReadFile(fromFile)
				if err != nil {
					return fmt.Errorf("read --from-file: %w", err)
				}
			} else {
				raw, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("read stdin: %w", err)
				}
			}
			value := strings.TrimRight(string(raw), "\r\n")
			if value == "" {
				return fmt.Errorf("noleak add: empty value")
			}

			resp, err := defaultClient().Call(&ipc.Request{
				Op: ipc.OpRegister,
				Register: &ipc.RegisterRequest{
					Value:    value,
					Kind:     kind,
					Source:   "manual:cli",
					Bindings: binds,
				},
			})
			if err != nil {
				return err
			}
			if resp.Error != "" {
				return fmt.Errorf("daemon: %s", resp.Error)
			}
			fmt.Println(resp.Register.Placeholder)
			return nil
		},
	}
	c.Flags().String("from-file", "", "read value from file instead of stdin")
	c.Flags().StringSlice("bind", nil, "destination host pattern(s) the secret may be substituted for")
	return c
}

func newListCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "list",
		Short: "List registered secrets (placeholders only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := defaultClient().Call(&ipc.Request{Op: ipc.OpList})
			if err != nil {
				return err
			}
			if resp.Error != "" {
				return fmt.Errorf("daemon: %s", resp.Error)
			}
			if resp.List == nil || len(resp.List.Entries) == 0 {
				fmt.Fprintln(os.Stderr, "(empty vault)")
				return nil
			}
			fmt.Printf("%-20s %-26s %-12s %-10s %s\n", "PLACEHOLDER", "KIND", "STATUS", "USES", "BINDINGS")
			for _, e := range resp.List.Entries {
				fmt.Printf("%-20s %-26s %-12s %-10d %s\n",
					e.Placeholder, e.Kind, e.Status, e.Uses, strings.Join(e.Bindings, ","))
			}
			return nil
		},
	}
	c.Flags().BoolP("all", "a", false, "include archived/rotated entries")
	return c
}

func newBindCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bind <placeholder> <host>...",
		Short: "Bind a placeholder to one or more allowed destination hosts",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := defaultClient().Call(&ipc.Request{
				Op:   ipc.OpBind,
				Bind: &ipc.BindRequest{Placeholder: args[0], Hosts: args[1:]},
			})
			if err != nil {
				return err
			}
			if resp.Error != "" {
				return fmt.Errorf("daemon: %s", resp.Error)
			}
			fmt.Fprintln(os.Stderr, "ok")
			return nil
		},
	}
}

func newReviewCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "review",
		Short: "Triage pending-review entries (auto-registered + bootstrap)",
		Long:  "See SPEC.md §7. Stage 9 work pending; this stub lists pending entries for now.",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := defaultClient().Call(&ipc.Request{Op: ipc.OpList})
			if err != nil {
				return err
			}
			if resp.Error != "" {
				return fmt.Errorf("daemon: %s", resp.Error)
			}
			any := false
			for _, e := range resp.List.Entries {
				if e.Status != "pending_review" {
					continue
				}
				any = true
				fmt.Printf("%s  %s  source=%s  bindings=%s\n",
					e.Placeholder, e.Kind, e.Source, strings.Join(e.Bindings, ","))
			}
			if !any {
				fmt.Fprintln(os.Stderr, "(no pending review entries)")
			}
			return nil
		},
	}
	c.Flags().Bool("bulk", false, "group by source dir + type for fast accept/reject (Stage 9)")
	return c
}

func newUnlockCmd() *cobra.Command {
	// Defined in unlock.go.
	return unlockCommand()
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon health, vault size, pending review count",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := defaultClient().Call(&ipc.Request{Op: ipc.OpHealth})
			if err != nil {
				return fmt.Errorf("daemon unreachable at %s: %w", defaultSocketPath(), err)
			}
			if resp.Error != "" {
				return fmt.Errorf("daemon: %s", resp.Error)
			}
			h := resp.Health
			fmt.Printf("noleakd %s\n", h.Version)
			fmt.Printf("  unlocked:        %v\n", h.Unlocked)
			fmt.Printf("  vault entries:   %d\n", h.VaultEntries)
			fmt.Printf("  pending review:  %d\n", h.PendingReview)
			fmt.Printf("  uptime seconds:  %d\n", h.UptimeSeconds)
			fmt.Printf("  socket:          %s\n", defaultSocketPath())
			return nil
		},
	}
}

func newRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <placeholder> <new-value-or-->",
		Short: "Atomically swap a secret's value. Use '-' to read new value from stdin.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ph, newValue := args[0], args[1]
			if newValue == "-" {
				raw, err := io.ReadAll(os.Stdin)
				if err != nil {
					return err
				}
				newValue = strings.TrimRight(string(raw), "\r\n")
			}
			resp, err := defaultClient().Call(&ipc.Request{
				Op:     ipc.OpRotate,
				Rotate: &ipc.RotateRequest{Placeholder: ph, NewValue: newValue},
			})
			if err != nil {
				return err
			}
			if resp.Error != "" {
				return fmt.Errorf("daemon: %s", resp.Error)
			}
			fmt.Fprintln(os.Stderr, "ok")
			return nil
		},
	}
}

func newRotateListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate-list",
		Short: "Print rotation worksheet (rotation-needed + pending entries) as CSV with provider hints",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := defaultClient().Call(&ipc.Request{Op: ipc.OpList})
			if err != nil {
				return err
			}
			if resp.Error != "" {
				return fmt.Errorf("daemon: %s", resp.Error)
			}
			w := csv.NewWriter(os.Stdout)
			w.Write([]string{"placeholder", "kind", "source", "bindings", "registered_at", "uses", "rotation_url"})
			for _, e := range resp.List.Entries {
				if e.Status != "rotation_needed" && e.Status != "pending_review" {
					continue
				}
				w.Write([]string{
					e.Placeholder, e.Kind, e.Source,
					strings.Join(e.Bindings, "|"),
					e.RegisteredAt,
					fmt.Sprintf("%d", e.Uses),
					rotationURLFor(e.Kind),
				})
			}
			w.Flush()
			return nil
		},
	}
}

func newDeleteCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "delete <placeholder>",
		Short: "Remove an entry from the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := defaultClient().Call(&ipc.Request{
				Op:     ipc.OpDelete,
				Delete: &ipc.DeleteRequest{Placeholder: args[0]},
			})
			if err != nil {
				return err
			}
			if resp.Error != "" {
				return fmt.Errorf("daemon: %s", resp.Error)
			}
			fmt.Fprintln(os.Stderr, "ok")
			return nil
		},
	}
	c.Flags().Bool("from-disk", false, "(stage 9) also offer to clean source files where the value was found")
	return c
}

// Compile-time guard: keep filepath imported so future expansion (e.g. config
// file resolution) doesn't need a re-import dance.
var _ = filepath.Join
