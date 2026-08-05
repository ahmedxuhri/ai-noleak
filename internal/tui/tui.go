package tui

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

// Run launches the interactive review TUI. It connects to the noleakd daemon
// at socketPath and blocks until the user quits. Returns an error if the
// program fails to start or the terminal is not interactive.
//
// If stdout is not a TTY (e.g. piped output), Run returns ErrNotTTY so the
// caller can fall back to plain-text listing.
func Run(socketPath string) error {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return ErrNotTTY
	}

	m := newModel(socketPath)
	p := tea.NewProgram(
		m,
		tea.WithAltScreen(),       // enter alternate screen buffer — no scroll pollution
		tea.WithMouseCellMotion(), // future: mouse click support
	)

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}

// ErrNotTTY is returned when stdout is not an interactive terminal.
var ErrNotTTY = fmt.Errorf("noleak review: stdout is not a TTY — use 'noleak list' for non-interactive output")
