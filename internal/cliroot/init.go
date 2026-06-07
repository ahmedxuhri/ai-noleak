package cliroot

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"noleak/internal/bootstrap"
	"noleak/internal/ipc"
)

// runInit drives the bootstrap harvester. The daemon must already be up.
// Used by `noleak init`.
func runInit(dryRun bool, roots []string) error {
	if dryRun {
		fmt.Fprintln(os.Stderr, "noleak init: --dry-run not yet implemented (no-op flag); proceeding with real harvest")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	start := time.Now()
	stats, err := bootstrap.Harvest(ctx, ipc.NewClient(defaultSocketPath()), bootstrap.Options{
		Roots: roots,
		Progress: func(s bootstrap.Stats) {
			fmt.Fprintf(os.Stderr, "  scanned %d files, %d secrets, %d errors\r",
				s.FilesScanned, s.NewSecrets, s.Errors)
		},
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "noleak init: done in %s\n", time.Since(start).Round(10*time.Millisecond))
	fmt.Fprintf(os.Stderr, "  files scanned:  %d\n", stats.FilesScanned)
	fmt.Fprintf(os.Stderr, "  files skipped:  %d (oversize / unreadable)\n", stats.FilesSkipped)
	fmt.Fprintf(os.Stderr, "  bytes scanned:  %d\n", stats.BytesScanned)
	fmt.Fprintf(os.Stderr, "  new secrets:    %d (status=pending_review)\n", stats.NewSecrets)
	fmt.Fprintf(os.Stderr, "  errors:         %d\n", stats.Errors)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "next: noleak review   to triage detected secrets")
	return nil
}
