// Command noleak is the user-facing CLI and the L1 PTY wrapper.
//
// Subcommands implement install/init, secret management, the review TUI,
// rotation, and daemon control. When invoked as `noleak <external-cmd>`
// with arguments that don't match a known subcommand, it falls through to
// the L1 PTY wrapper.
//
// See SPEC.md §5 (L1), §7, §9.
package main

import (
	"fmt"
	"os"

	"noleak/internal/cliroot"
)

func main() {
	if err := cliroot.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
