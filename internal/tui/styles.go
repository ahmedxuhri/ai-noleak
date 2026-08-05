package tui

import "github.com/charmbracelet/lipgloss"

// Palette — dark terminal colours tuned for 256-colour + true-colour terminals.
var (
	colBackground = lipgloss.AdaptiveColor{Light: "#F5F5F5", Dark: "#1A1B26"}
	colSurface    = lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#24283B"}
	colBorder     = lipgloss.AdaptiveColor{Light: "#C0CAF5", Dark: "#414868"}
	colAccent     = lipgloss.AdaptiveColor{Light: "#7C3AED", Dark: "#BB9AF7"}
	colText       = lipgloss.AdaptiveColor{Light: "#1A1B26", Dark: "#C0CAF5"}
	colMuted      = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#565F89"}

	colGreen  = lipgloss.AdaptiveColor{Light: "#16A34A", Dark: "#9ECE6A"}
	colRed    = lipgloss.AdaptiveColor{Light: "#DC2626", Dark: "#F7768E"}
	colYellow = lipgloss.AdaptiveColor{Light: "#D97706", Dark: "#E0AF68"}
	colOrange = lipgloss.AdaptiveColor{Light: "#EA580C", Dark: "#FF9E64"}
	colBlue   = lipgloss.AdaptiveColor{Light: "#2563EB", Dark: "#7AA2F7"}
)

// Pane styles.
var (
	styleListPane = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colBorder).
			Padding(0, 1)

	styleDetailPane = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colAccent).
			Padding(0, 1)

	styleDetailPaneInactive = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(colBorder).
				Padding(0, 1)
)

// Text styles.
var (
	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colAccent)

	styleSubtle = lipgloss.NewStyle().
			Foreground(colMuted)

	styleKey = lipgloss.NewStyle().
			Bold(true).
			Foreground(colBlue)

	stylePlaceholder = lipgloss.NewStyle().
				Bold(true).
				Foreground(colAccent)

	styleValue = lipgloss.NewStyle().
			Foreground(colText)

	styleSelectedItem = lipgloss.NewStyle().
				Bold(true).
				Foreground(colAccent)

	styleNormalItem = lipgloss.NewStyle().
			Foreground(colText)

	// Help bar at the bottom.
	styleHelp = lipgloss.NewStyle().
			Foreground(colMuted).
			Padding(0, 1)

	// Input prompt.
	styleInput = lipgloss.NewStyle().
			Foreground(colText).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(colAccent).
			BorderBottom(true).
			Padding(0, 1)

	// Confirm prompt.
	styleConfirm = lipgloss.NewStyle().
			Bold(true).
			Foreground(colRed)

	// Error flash.
	styleError = lipgloss.NewStyle().
			Bold(true).
			Foreground(colRed)

	// Success flash.
	styleSuccess = lipgloss.NewStyle().
			Bold(true).
			Foreground(colGreen)
)

// statusBadge renders a coloured pill for each vault lifecycle state.
func statusBadge(status string) string {
	var col lipgloss.TerminalColor
	var label string
	switch status {
	case "pending_review":
		col = colYellow
		label = " PENDING "
	case "accepted":
		col = colGreen
		label = " ACCEPTED"
	case "rejected":
		col = colRed
		label = " REJECTED"
	case "rotation_needed":
		col = colOrange
		label = " ROTATE  "
	case "archived":
		col = colMuted
		label = " ARCHIVED"
	default:
		col = colMuted
		label = " UNKNOWN "
	}
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#1A1B26")).
		Background(col).
		Padding(0, 1).
		Render(label)
}
