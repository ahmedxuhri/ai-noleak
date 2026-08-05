package tui

import "github.com/charmbracelet/bubbles/key"

// keyMap defines all interactive key bindings for the review TUI.
type keyMap struct {
	Up     key.Binding
	Down   key.Binding
	Accept key.Binding
	Reject key.Binding
	Rotate key.Binding
	Delete key.Binding
	Bind   key.Binding
	Unbind key.Binding
	Help   key.Binding
	Quit   key.Binding
}

// defaultKeyMap returns the standard key bindings.
func defaultKeyMap() keyMap {
	return keyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		Accept: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "accept"),
		),
		Reject: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "reject"),
		),
		Rotate: key.NewBinding(
			key.WithKeys("n"),
			key.WithHelp("n", "rotation needed"),
		),
		Delete: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", "delete"),
		),
		Bind: key.NewBinding(
			key.WithKeys("b"),
			key.WithHelp("b", "bind host"),
		),
		Unbind: key.NewBinding(
			key.WithKeys("u"),
			key.WithHelp("u", "unbind host"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}
}

// shortHelp returns the compact help row shown at the bottom of the TUI.
// It returns progressively shorter versions so the caller can pick one
// that fits the terminal width.
func (k keyMap) shortHelp() string {
	bindings := []struct{ key, desc string }{
		{"↑/↓", "navigate"},
		{"a", "accept"},
		{"r", "reject"},
		{"n", "rotate"},
		{"d", "delete"},
		{"b", "bind"},
		{"u", "unbind"},
		{"?", "help"},
		{"q", "quit"},
	}
	out := ""
	for _, b := range bindings {
		out += styleKey.Render(b.key) + styleSubtle.Render(" "+b.desc+"  ")
	}
	return out
}

// shortHelpCompact returns a minimal one-liner for narrow terminals.
func (k keyMap) shortHelpCompact() string {
	return styleSubtle.Render("a·accept  r·reject  n·rotate  d·del  b·bind  u·unbind  ?·help  q·quit")
}

// shortHelpTiny returns an ultra-compressed version for very narrow terminals.
func (k keyMap) shortHelpTiny() string {
	return styleSubtle.Render("a·acc  r·rej  n·rot  d·del  b/u·bind  ?  q")
}

// fullHelp returns the expanded help overlay text.
func (k keyMap) fullHelp() string {
	rows := []struct{ key, desc string }{
		{"↑ / k", "Move selection up"},
		{"↓ / j", "Move selection down"},
		{"a", "Accept entry → mark as accepted"},
		{"r", "Reject entry → mark as rejected"},
		{"n", "Mark entry as rotation_needed"},
		{"d", "Delete entry (prompts for confirmation)"},
		{"b", "Bind a host pattern to entry (opens input)"},
		{"u", "Unbind a host pattern from entry (opens input)"},
		{"?", "Toggle this help overlay"},
		{"q / ctrl+c", "Quit"},
	}
	out := styleTitle.Render("Key Bindings") + "\n\n"
	for _, r := range rows {
		out += styleKey.Render(r.key) + styleSubtle.Render("  —  ") + styleValue.Render(r.desc) + "\n"
	}
	return out
}
