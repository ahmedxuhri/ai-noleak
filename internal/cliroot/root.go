// Package cliroot wires the noleak top-level command tree.
package cliroot

import (
	"errors"

	"github.com/spf13/cobra"
)

const version = "0.0.0-dev"

// Execute runs the root command.
func Execute() error {
	root := &cobra.Command{
		Use:           "noleak",
		Short:         "Local secret-leak prevention for agentic AI CLIs",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newInitCmd(),
		newAddCmd(),
		newListCmd(),
		newBindCmd(),
		newReviewCmd(),
		newUnlockCmd(),
		newStatusCmd(),
		newDoctorCmd(),
		newRotateCmd(),
		newRotateListCmd(),
		newDeleteCmd(),
		newHookCmd(),
		newRunCmd(),
		newProxyCmd(),
	)

	return root.Execute()
}

func notImplemented(section string) error {
	return errors.New("not implemented yet — see SPEC.md " + section)
}
