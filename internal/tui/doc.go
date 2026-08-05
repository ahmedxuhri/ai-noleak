// Package tui provides the interactive terminal UI for `noleak review`.
//
// It is built on the Bubbletea Elm-architecture event loop with Bubbles
// components and Lipgloss styling. The UI connects to the running noleakd
// daemon over the same Unix domain socket used by all other CLI commands.
//
// Entry point: Run(socketPath string) error
package tui
