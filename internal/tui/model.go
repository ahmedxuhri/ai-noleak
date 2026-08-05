package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"noleak/internal/ipc"
)

// uiState tracks which interactive overlay is active.
type uiState int

const (
	stateList    uiState = iota // normal navigation
	stateConfirm                // delete confirmation prompt
	stateInput                  // host bind/unbind text input
	stateHelp                   // full help overlay
)

// inputMode distinguishes bind vs unbind host input so both share stateInput.
type inputMode int

const (
	inputModeBind   inputMode = iota
	inputModeUnbind
)

const (
	refreshInterval = 3 * time.Second
	flashDuration   = 4 * time.Second
)

// tickMsg is the periodic refresh signal.
type tickMsg time.Time

// clearFlashMsg clears the flash notice after flashDuration.
type clearFlashMsg struct{}

// listMsg carries a fresh vault listing from the daemon.
type listMsg struct {
	entries []ipc.ListEntry
	err     error
}

// actionMsg carries the result of an IPC mutation (set_status, delete, bind).
type actionMsg struct {
	err    error
	notice string
}

// model is the Bubbletea application model.
type model struct {
	socketPath string
	keys       keyMap

	// Vault state.
	entries      []ipc.ListEntry
	cursor       int
	scrollOffset int
	fetchErr     error

	// UI state.
	state     uiState
	inputMode inputMode
	input     textinput.Model
	flash     string
	flashOK   bool

	// Terminal dimensions.
	width  int
	height int
}

// newModel constructs the initial model.
func newModel(socketPath string) model {
	ti := textinput.New()
	ti.Placeholder = "api.example.com"
	ti.CharLimit = 253

	return model{
		socketPath: socketPath,
		keys:       defaultKeyMap(),
		input:      ti,
	}
}

// ── Tea interface ─────────────────────────────────────────────────────────────

func (m model) Init() tea.Cmd {
	return tea.Batch(fetchList(m.socketPath), tickCmd())
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		return m, tea.Batch(fetchList(m.socketPath), tickCmd())

	case listMsg:
		if msg.err != nil {
			m.fetchErr = msg.err
		} else {
			m.fetchErr = nil
			m.entries = msg.entries
			// Clamp cursor and scrollOffset so they stay valid after vault mutations.
			if len(m.entries) == 0 {
				m.cursor = 0
				m.scrollOffset = 0
			} else {
				if m.cursor >= len(m.entries) {
					m.cursor = len(m.entries) - 1
				}
				if m.scrollOffset > m.cursor {
					m.scrollOffset = m.cursor
				}
			}
		}
		return m, nil

	case clearFlashMsg:
		m.flash = ""
		return m, nil

	case actionMsg:
		if msg.err != nil {
			m.flash = msg.err.Error()
			m.flashOK = false
		} else {
			m.flash = msg.notice
			m.flashOK = true
		}
		// Refresh list after any vault mutation + schedule flash auto-clear.
		return m, tea.Batch(fetchList(m.socketPath), clearFlashCmd())

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// ── Input mode (bind/unbind host) ──────────────────────────────────────
	if m.state == stateInput {
		switch msg.String() {
		case "enter":
			host := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			m.input.Blur()
			m.state = stateList
			if host == "" {
				return m, nil
			}
			e := m.selected()
			if e == nil {
				// Entry vanished during the input — silently cancel.
				return m, nil
			}
			if m.inputMode == inputModeBind {
				return m, bindHost(m.socketPath, e.Placeholder, host)
			}
			return m, unbindHost(m.socketPath, e.Placeholder, host)

		case "esc":
			m.input.SetValue("")
			m.input.Blur()
			m.state = stateList
			return m, nil
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}

	// ── Confirm mode (delete) ───────────────────────────────────────────────
	if m.state == stateConfirm {
		// Always leave confirm state on any keypress.
		m.state = stateList
		if msg.String() == "y" || msg.String() == "enter" {
			e := m.selected()
			if e == nil {
				// Entry disappeared (race with background refresh) — cancel silently.
				return m, nil
			}
			return m, deleteEntry(m.socketPath, e.Placeholder)
		}
		return m, nil
	}

	// ── Help overlay ────────────────────────────────────────────────────────
	if m.state == stateHelp {
		m.state = stateList
		return m, nil
	}

	// ── Normal navigation ───────────────────────────────────────────────────
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "?":
		m.state = stateHelp
		m.flash = ""

	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
			m.flash = ""
			// Scroll up if cursor leaves visible window.
			if m.cursor < m.scrollOffset {
				m.scrollOffset = m.cursor
			}
		}

	case "down", "j":
		if m.cursor < len(m.entries)-1 {
			m.cursor++
			m.flash = ""
			// Scroll down if cursor leaves visible window.
			vis := m.listVisibleLines()
			if m.cursor >= m.scrollOffset+vis {
				m.scrollOffset = m.cursor - vis + 1
			}
		}

	case "a":
		if e := m.selected(); e != nil {
			return m, setStatus(m.socketPath, e.Placeholder, "accepted")
		}

	case "r":
		if e := m.selected(); e != nil {
			return m, setStatus(m.socketPath, e.Placeholder, "rejected")
		}

	case "n":
		if e := m.selected(); e != nil {
			return m, setStatus(m.socketPath, e.Placeholder, "rotation_needed")
		}

	case "d":
		if m.selected() != nil {
			m.state = stateConfirm
		}

	case "b":
		if m.selected() != nil {
			m.state = stateInput
			m.inputMode = inputModeBind
			m.input.Placeholder = "api.example.com"
			m.input.Focus()
			return m, textinput.Blink
		}

	case "u":
		// Only open unbind if the entry actually has bindings to remove.
		if e := m.selected(); e != nil && len(e.Bindings) > 0 {
			m.state = stateInput
			m.inputMode = inputModeUnbind
			m.input.Placeholder = "host to remove"
			m.input.Focus()
			return m, textinput.Blink
		}
	}
	return m, nil
}

// selected returns the currently highlighted entry, or nil if the list is
// empty or the cursor is out-of-bounds (can happen after a background refresh).
func (m model) selected() *ipc.ListEntry {
	if len(m.entries) == 0 || m.cursor < 0 || m.cursor >= len(m.entries) {
		return nil
	}
	e := m.entries[m.cursor]
	return &e
}

// listVisibleLines returns how many list rows fit inside the list pane.
// Accounts for 1 header row, 1 footer row, and 2 rows of pane border.
func (m model) listVisibleLines() int {
	h := m.height - 6
	if h < 1 {
		return 1
	}
	return h
}

// ── View ──────────────────────────────────────────────────────────────────────

func (m model) View() string {
	if m.width == 0 {
		return "Loading…"
	}

	if m.state == stateHelp {
		return m.renderHelp()
	}

	// 40% list / 60% detail split, accounting for borders and gap.
	listW := m.width*40/100 - 4
	detailW := m.width - listW - 8

	paneH := m.height - 4 // header(1) + footer(1) + 2 border rows = 4
	listBox := styleListPane.Width(listW).Height(paneH).Render(m.renderList(listW))
	var detailBox string
	if m.selected() != nil {
		detailBox = styleDetailPane.Width(detailW).Height(paneH).Render(m.renderDetail(detailW))
	} else {
		detailBox = styleDetailPaneInactive.Width(detailW).Height(paneH).Render(m.renderDetail(detailW))
	}

	body := lipgloss.JoinHorizontal(lipgloss.Top, listBox, "  ", detailBox)
	return lipgloss.JoinVertical(lipgloss.Left, m.renderHeader(), body, m.renderFooter())
}

func (m model) renderHeader() string {
	title := styleTitle.Render("  ai-noleak · Secret Review")
	pending := 0
	for _, e := range m.entries {
		if e.Status == "pending_review" {
			pending++
		}
	}
	badge := ""
	if pending > 0 {
		badge = "  " + lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#1A1B26")).
			Background(colYellow).
			Padding(0, 1).
			Render(fmt.Sprintf(" %d pending ", pending))
	}
	var info string
	if m.fetchErr != nil {
		info = styleError.Render("  ⚠ daemon unreachable")
	} else {
		info = styleSubtle.Render(fmt.Sprintf("  %d total", len(m.entries)))
	}
	return title + badge + info
}

func (m model) renderList(width int) string {
	if len(m.entries) == 0 {
		return styleSubtle.Render("(no entries)")
	}

	vis := m.listVisibleLines()
	end := m.scrollOffset + vis
	if end > len(m.entries) {
		end = len(m.entries)
	}

	var sb strings.Builder
	for i := m.scrollOffset; i < end; i++ {
		e := m.entries[i]
		cur := "  "
		nameStyle := styleNormalItem
		if i == m.cursor {
			cur = "▶ "
			nameStyle = styleSelectedItem
		}
		badge := statusBadge(e.Status)
		// nameW = total width minus: cursor(2) + badge(~11) + gap(2).
		nameW := width - 15
		if nameW < 8 {
			nameW = 8
		}
		name := nameStyle.Width(nameW).Render(e.Placeholder)
		sb.WriteString(cur + badge + "  " + name + "\n")
	}

	// Scroll indicator — only shown when the list overflows the pane.
	if len(m.entries) > vis {
		sb.WriteString(styleSubtle.Render(fmt.Sprintf("  %d–%d / %d", m.scrollOffset+1, end, len(m.entries))))
	}

	return strings.TrimRight(sb.String(), "\n")
}

func (m model) renderDetail(width int) string {
	e := m.selected()
	if e == nil {
		return styleSubtle.Render("Select an entry to review")
	}

	var sb strings.Builder

	sb.WriteString(stylePlaceholder.Render(e.Placeholder) + "\n")
	sb.WriteString(statusBadge(e.Status) + "\n\n")

	field := func(label, value string) string {
		return styleKey.Render(label+":") + "  " + styleValue.Render(value) + "\n"
	}
	sb.WriteString(field("Kind", e.Kind))
	sb.WriteString(field("Source", e.Source))
	sb.WriteString(field("Registered", e.RegisteredAt))
	sb.WriteString(field("Uses", fmt.Sprintf("%d", e.Uses)))

	bindings := "(none)"
	if len(e.Bindings) > 0 {
		bindings = strings.Join(e.Bindings, ", ")
	}
	sb.WriteString(field("Bindings", bindings))
	sb.WriteString("\n")

	// Active overlay prompts.
	switch m.state {
	case stateConfirm:
		sb.WriteString(
			styleConfirm.Render("Delete this entry? ") +
				styleKey.Render("[y/enter]") + styleSubtle.Render(" yes  ") +
				styleKey.Render("[any]") + styleSubtle.Render(" cancel") + "\n")

	case stateInput:
		label := "Bind host:"
		if m.inputMode == inputModeUnbind {
			label = "Unbind host:"
		}
		sb.WriteString(styleKey.Render(label) + "\n")
		// Render the textinput component directly — no Lipgloss wrapper to
		// avoid double-border visual artifacts on the input field.
		sb.WriteString("  " + m.input.View() + "\n")
		sb.WriteString(styleSubtle.Render("  enter·confirm   esc·cancel") + "\n")
	}

	// Flash notice.
	if m.flash != "" {
		sb.WriteString("\n")
		if m.flashOK {
			sb.WriteString(styleSuccess.Render("✓ " + m.flash))
		} else {
			sb.WriteString(styleError.Render("✗ " + m.flash))
		}
	}

	return sb.String()
}

func (m model) renderHelp() string {
	box := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(colAccent).
		Padding(1, 3).
		Width(m.width / 2).
		Render(m.keys.fullHelp())
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

func (m model) renderFooter() string {
	// Pick the widest help string that still fits the terminal width.
	for _, candidate := range []string{
		m.keys.shortHelp(),
		m.keys.shortHelpCompact(),
		m.keys.shortHelpTiny(),
	} {
		if m.width == 0 || lipgloss.Width(candidate) <= m.width {
			return styleHelp.Render(candidate)
		}
	}
	return ""
}

// ── Commands ──────────────────────────────────────────────────────────────────

func tickCmd() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func clearFlashCmd() tea.Cmd {
	return tea.Tick(flashDuration, func(t time.Time) tea.Msg { return clearFlashMsg{} })
}

func fetchList(socketPath string) tea.Cmd {
	return func() tea.Msg {
		resp, err := ipc.NewClient(socketPath).Call(&ipc.Request{Op: ipc.OpList})
		if err != nil {
			return listMsg{err: err}
		}
		if resp.Error != "" {
			return listMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		return listMsg{entries: resp.List.Entries}
	}
}

func setStatus(socketPath, placeholder, status string) tea.Cmd {
	return func() tea.Msg {
		resp, err := ipc.NewClient(socketPath).Call(&ipc.Request{
			Op:        ipc.OpSetStatus,
			SetStatus: &ipc.SetStatusRequest{Placeholder: placeholder, Status: status},
		})
		if err != nil {
			return actionMsg{err: err}
		}
		if resp.Error != "" {
			return actionMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		return actionMsg{notice: fmt.Sprintf("%s → %s", placeholder, status)}
	}
}

func deleteEntry(socketPath, placeholder string) tea.Cmd {
	return func() tea.Msg {
		resp, err := ipc.NewClient(socketPath).Call(&ipc.Request{
			Op:     ipc.OpDelete,
			Delete: &ipc.DeleteRequest{Placeholder: placeholder},
		})
		if err != nil {
			return actionMsg{err: err}
		}
		if resp.Error != "" {
			return actionMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		return actionMsg{notice: fmt.Sprintf("deleted %s", placeholder)}
	}
}

func bindHost(socketPath, placeholder, host string) tea.Cmd {
	return func() tea.Msg {
		resp, err := ipc.NewClient(socketPath).Call(&ipc.Request{
			Op:   ipc.OpBind,
			Bind: &ipc.BindRequest{Placeholder: placeholder, Hosts: []string{host}},
		})
		if err != nil {
			return actionMsg{err: err}
		}
		if resp.Error != "" {
			return actionMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		return actionMsg{notice: fmt.Sprintf("bound %s → %s", placeholder, host)}
	}
}

func unbindHost(socketPath, placeholder, host string) tea.Cmd {
	return func() tea.Msg {
		resp, err := ipc.NewClient(socketPath).Call(&ipc.Request{
			Op:     ipc.OpUnbind,
			Unbind: &ipc.BindRequest{Placeholder: placeholder, Hosts: []string{host}},
		})
		if err != nil {
			return actionMsg{err: err}
		}
		if resp.Error != "" {
			return actionMsg{err: fmt.Errorf("%s", resp.Error)}
		}
		return actionMsg{notice: fmt.Sprintf("unbound %s from %s", placeholder, host)}
	}
}
