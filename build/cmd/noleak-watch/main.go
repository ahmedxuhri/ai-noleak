// Command noleak-watch is the inotify daemon for sensitive-path purge/redact.
// See SPEC.md §5 L5.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"noleak/internal/ipc"
	"noleak/internal/watch"
)

const version = "0.0.0-dev"

func main() {
	var (
		socketPath = flag.String("socket", defaultSocket(), "noleakd socket path")
		extraRedact = flag.String("redact", "", "comma-separated extra paths to redact")
		extraPurge  = flag.String("purge", "", "comma-separated extra paths to purge")
	)
	flag.Parse()

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "noleak-watch: %v\n", err)
		os.Exit(1)
	}

	w := watch.New(ipc.NewClient(*socketPath), nil)
	for _, r := range watch.DefaultRules(home) {
		w.AddRule(r)
	}
	for _, p := range splitCSV(*extraRedact) {
		w.AddRule(watch.Rule{Path: p, Action: watch.ActionRedact})
	}
	for _, p := range splitCSV(*extraPurge) {
		w.AddRule(watch.Rule{Path: p, Action: watch.ActionPurge})
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "noleak-watch %s\n", version)
	if err := w.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "noleak-watch: %v\n", err)
		os.Exit(1)
	}
}

func defaultSocket() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".noleak", "sock")
	}
	return "/tmp/noleak.sock"
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
