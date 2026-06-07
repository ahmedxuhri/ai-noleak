package cliroot

import (
	"github.com/spf13/cobra"

	"noleak/internal/ipc"
	"noleak/internal/wrapper"
)

// newRunCmd wraps an external command (e.g. `noleak run claude`) inside a
// PTY with the L1 paste-detection filter enabled. SPEC.md §5 L1.
func newRunCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "run <cmd> [args...]",
		Short: "Run a command inside the noleak L1 PTY wrapper (paste-time secret detection)",
		Args:  cobra.MinimumNArgs(1),
		// Disable cobra's automatic flag parsing for the wrapped command's
		// own flags. Everything after `run` belongs to the inner command.
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return wrapper.Run(wrapper.RunOpts{
				Argv:         args,
				Client:       ipc.NewClient(defaultSocketPath()),
				AutoRegister: true,
			})
		},
	}
	return c
}
