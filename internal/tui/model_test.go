package tui

import (
	"fmt"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"noleak/internal/ipc"
)

// buildModel returns a model pre-loaded with test entries.
func buildModel(entries []ipc.ListEntry) model {
	m := newModel("/nonexistent/test.sock")
	m.width = 200
	m.height = 40
	m.entries = entries
	return m
}

var testEntries = []ipc.ListEntry{
	{Placeholder: "@TOKEN_aabbcc@", Kind: "aws_access_key_id", Source: "bootstrap:~/.aws", Status: "pending_review", Uses: 2},
	{Placeholder: "@TOKEN_112233@", Kind: "github_token", Source: "proxy:intercept", Status: "accepted", Uses: 5},
	{Placeholder: "@TOKEN_445566@", Kind: "openai_api_key", Source: "manual:cli", Status: "rejected", Uses: 0},
}

// keypress is a helper to send a single rune key message.
func keypress(m model, k string) (model, tea.Cmd) {
	m2, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
	return m2.(model), cmd
}

// keypressSpecial sends a special key (e.g. tea.KeyEsc).
func keypressSpecial(m model, t tea.KeyType) (model, tea.Cmd) {
	m2, cmd := m.Update(tea.KeyMsg{Type: t})
	return m2.(model), cmd
}

// ── Basic state ───────────────────────────────────────────────────────────────

func TestInitialState(t *testing.T) {
	m := buildModel(testEntries)
	if m.cursor != 0 {
		t.Fatalf("expected cursor=0, got %d", m.cursor)
	}
	if m.state != stateList {
		t.Fatalf("expected stateList, got %d", m.state)
	}
	if m.scrollOffset != 0 {
		t.Fatalf("expected scrollOffset=0, got %d", m.scrollOffset)
	}
}

// ── Navigation ────────────────────────────────────────────────────────────────

func TestNavigationDown(t *testing.T) {
	m := buildModel(testEntries)
	m2, _ := keypress(m, "j")
	if m2.cursor != 1 {
		t.Fatalf("expected cursor=1 after down, got %d", m2.cursor)
	}
}

func TestNavigationUpClamped(t *testing.T) {
	m := buildModel(testEntries)
	m2, _ := keypress(m, "k")
	if m2.cursor != 0 {
		t.Fatalf("expected cursor clamped at 0, got %d", m2.cursor)
	}
}

func TestNavigationDownClamped(t *testing.T) {
	m := buildModel(testEntries)
	m.cursor = len(testEntries) - 1
	m2, _ := keypress(m, "j")
	if m2.cursor != len(testEntries)-1 {
		t.Fatalf("expected cursor clamped at end, got %d", m2.cursor)
	}
}

func TestNavigationClearsFlash(t *testing.T) {
	m := buildModel(testEntries)
	m.flash = "stale message"
	m2, _ := keypress(m, "j")
	if m2.flash != "" {
		t.Fatalf("navigation should clear flash, got %q", m2.flash)
	}
}

// ── Scrolling ─────────────────────────────────────────────────────────────────

func TestScrollingDownUpdatesOffset(t *testing.T) {
	// 30 entries, small window so scrolling kicks in.
	entries := make([]ipc.ListEntry, 30)
	for i := range entries {
		entries[i] = ipc.ListEntry{
			Placeholder: fmt.Sprintf("@TOKEN_%06d@", i),
			Kind:        "test",
			Status:      "pending_review",
		}
	}
	m := buildModel(entries)
	m.height = 15 // listVisibleLines = 15-6 = 9

	vis := m.listVisibleLines()
	// Drive cursor past the visible window.
	for i := 0; i <= vis; i++ {
		m, _ = keypress(m, "j")
	}
	if m.scrollOffset == 0 {
		t.Fatal("expected scrollOffset > 0 after scrolling past visible window")
	}
	if m.cursor != vis+1 {
		t.Fatalf("expected cursor=%d, got %d", vis+1, m.cursor)
	}
}

func TestScrollingUpAdjustsOffset(t *testing.T) {
	entries := make([]ipc.ListEntry, 20)
	for i := range entries {
		entries[i] = ipc.ListEntry{Placeholder: fmt.Sprintf("@TOKEN_%06d@", i), Status: "pending_review"}
	}
	m := buildModel(entries)
	m.height = 15
	m.cursor = 15
	m.scrollOffset = 10

	m2, _ := keypress(m, "k")
	if m2.cursor != 14 {
		t.Fatalf("expected cursor=14, got %d", m2.cursor)
	}
	// scrollOffset should stay ≤ cursor.
	if m2.scrollOffset > m2.cursor {
		t.Fatalf("scrollOffset (%d) > cursor (%d)", m2.scrollOffset, m2.cursor)
	}
}

func TestScrollOffsetClampsOnRefresh(t *testing.T) {
	m := buildModel(testEntries)
	m.cursor = 2
	m.scrollOffset = 2

	// Simulate vault refresh that removes all but one entry.
	m2, _ := m.Update(listMsg{entries: testEntries[:1]})
	m3 := m2.(model)
	if m3.cursor != 0 {
		t.Fatalf("expected cursor clamped to 0, got %d", m3.cursor)
	}
	if m3.scrollOffset != 0 {
		t.Fatalf("expected scrollOffset clamped to 0, got %d", m3.scrollOffset)
	}
}

func TestEmptyListAfterRefresh(t *testing.T) {
	m := buildModel(testEntries)
	m.cursor = 1
	m2, _ := m.Update(listMsg{entries: nil})
	m3 := m2.(model)
	if m3.cursor != 0 {
		t.Fatalf("expected cursor=0 for empty list, got %d", m3.cursor)
	}
	if m3.scrollOffset != 0 {
		t.Fatalf("expected scrollOffset=0 for empty list, got %d", m3.scrollOffset)
	}
}

// ── Help overlay ──────────────────────────────────────────────────────────────

func TestHelpOverlay(t *testing.T) {
	m := buildModel(testEntries)
	m2, _ := keypress(m, "?")
	if m2.state != stateHelp {
		t.Fatal("expected stateHelp after '?'")
	}
	// Any key dismisses help.
	m3, _ := keypress(m2, "x")
	if m3.state != stateList {
		t.Fatal("expected stateList after dismissing help")
	}
}

// ── Delete confirm ────────────────────────────────────────────────────────────

func TestDeleteConfirmEntered(t *testing.T) {
	m := buildModel(testEntries)
	m2, _ := keypress(m, "d")
	if m2.state != stateConfirm {
		t.Fatal("expected stateConfirm after 'd'")
	}
}

func TestDeleteConfirmCancel(t *testing.T) {
	m := buildModel(testEntries)
	m2, _ := keypress(m, "d")
	// Any key other than y/enter cancels.
	m3, _ := keypress(m2, "x")
	if m3.state != stateList {
		t.Fatal("expected stateList after cancel")
	}
}

func TestDeleteConfirmNilSafe(t *testing.T) {
	// BUG#1 regression test: selected() must not panic when entry disappears
	// between pressing 'd' and pressing 'y'.
	m := buildModel(testEntries)
	m2, _ := keypress(m, "d")
	if m2.state != stateConfirm {
		t.Fatal("expected stateConfirm")
	}
	// Background refresh removes all entries.
	m3, _ := m2.Update(listMsg{entries: nil})
	// Confirm — selected() is now nil — must not panic, must silently cancel.
	m4, _ := keypress(m3.(model), "y")
	if m4.state != stateList {
		t.Fatalf("expected stateList after nil-safe cancel, got %d", m4.state)
	}
}

func TestDeleteConfirmNoEntries(t *testing.T) {
	m := buildModel(nil)
	// 'd' on empty vault should not enter confirm.
	m2, _ := keypress(m, "d")
	if m2.state != stateList {
		t.Fatal("expected stateList when no entries to delete")
	}
}

// ── Bind/Unbind input ─────────────────────────────────────────────────────────

func TestBindInputOpened(t *testing.T) {
	m := buildModel(testEntries)
	m2, _ := keypress(m, "b")
	if m2.state != stateInput {
		t.Fatal("expected stateInput after 'b'")
	}
	if m2.inputMode != inputModeBind {
		t.Fatal("expected inputModeBind")
	}
}

func TestBindInputEscCancel(t *testing.T) {
	m := buildModel(testEntries)
	m2, _ := keypress(m, "b")
	m3, _ := keypressSpecial(m2, tea.KeyEsc)
	if m3.state != stateList {
		t.Fatal("expected stateList after esc")
	}
}

func TestUnbindInputOpened(t *testing.T) {
	entries := []ipc.ListEntry{
		{Placeholder: "@TOKEN_aabbcc@", Kind: "test", Status: "accepted",
			Bindings: []string{"api.example.com"}},
	}
	m := buildModel(entries)
	m2, _ := keypress(m, "u")
	if m2.state != stateInput {
		t.Fatal("expected stateInput after 'u' with bindings")
	}
	if m2.inputMode != inputModeUnbind {
		t.Fatal("expected inputModeUnbind")
	}
}

func TestUnbindIgnoredWhenNoBindings(t *testing.T) {
	// testEntries[0] has no bindings; 'u' should be a no-op.
	m := buildModel(testEntries)
	m2, _ := keypress(m, "u")
	if m2.state != stateList {
		t.Fatalf("expected stateList when entry has no bindings, got %d", m2.state)
	}
}

func TestUnbindIgnoredWhenNoEntries(t *testing.T) {
	m := buildModel(nil)
	m2, _ := keypress(m, "u")
	if m2.state != stateList {
		t.Fatal("expected stateList when vault is empty")
	}
}

// ── Flash notices ─────────────────────────────────────────────────────────────

func TestFlashSetOnActionSuccess(t *testing.T) {
	m := buildModel(testEntries)
	m2, _ := m.Update(actionMsg{notice: "done"})
	m3 := m2.(model)
	if m3.flash != "done" {
		t.Fatalf("expected flash='done', got %q", m3.flash)
	}
	if !m3.flashOK {
		t.Fatal("expected flashOK=true")
	}
}

func TestFlashSetOnActionError(t *testing.T) {
	m := buildModel(testEntries)
	m2, _ := m.Update(actionMsg{err: fmt.Errorf("boom")})
	m3 := m2.(model)
	if m3.flash != "boom" {
		t.Fatalf("expected flash='boom', got %q", m3.flash)
	}
	if m3.flashOK {
		t.Fatal("expected flashOK=false")
	}
}

func TestFlashAutoClear(t *testing.T) {
	// clearFlashMsg must wipe the flash field.
	m := buildModel(testEntries)
	m.flash = "old message"
	m.flashOK = true
	m2, _ := m.Update(clearFlashMsg{})
	if m2.(model).flash != "" {
		t.Fatalf("expected flash cleared, got %q", m2.(model).flash)
	}
}

// ── selected() ────────────────────────────────────────────────────────────────

func TestSelectedEmpty(t *testing.T) {
	m := buildModel(nil)
	if m.selected() != nil {
		t.Fatal("expected nil selected for empty vault")
	}
}

func TestSelectedOutOfBounds(t *testing.T) {
	m := buildModel(testEntries)
	m.cursor = 999
	if m.selected() != nil {
		t.Fatal("expected nil selected when cursor is out of bounds")
	}
}

func TestSelectedValid(t *testing.T) {
	m := buildModel(testEntries)
	m.cursor = 1
	e := m.selected()
	if e == nil {
		t.Fatal("expected non-nil selected")
	}
	if e.Placeholder != testEntries[1].Placeholder {
		t.Fatalf("wrong entry: got %s", e.Placeholder)
	}
}

// ── listVisibleLines ──────────────────────────────────────────────────────────

func TestListVisibleLinesMinimum(t *testing.T) {
	m := buildModel(nil)
	m.height = 1 // pathologically small
	if m.listVisibleLines() < 1 {
		t.Fatal("listVisibleLines must be >= 1")
	}
}

// ── View rendering ────────────────────────────────────────────────────────────

func TestViewDoesNotPanic(t *testing.T) {
	m := buildModel(testEntries)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("View() panicked: %v", r)
		}
	}()
	_ = m.View()
}

func TestViewEmptyVault(t *testing.T) {
	m := buildModel(nil)
	v := m.View()
	if v == "" {
		t.Fatal("View() returned empty string for empty vault")
	}
}

func TestViewHelpOverlay(t *testing.T) {
	m := buildModel(testEntries)
	m.state = stateHelp
	v := m.View()
	if v == "" {
		t.Fatal("help overlay View() returned empty string")
	}
}

func TestViewConfirmPrompt(t *testing.T) {
	m := buildModel(testEntries)
	m.state = stateConfirm
	v := m.View()
	if v == "" {
		t.Fatal("confirm View() returned empty string")
	}
}

func TestViewInputPrompt(t *testing.T) {
	m := buildModel(testEntries)
	m.state = stateInput
	m.inputMode = inputModeBind
	v := m.View()
	if v == "" {
		t.Fatal("input View() returned empty string")
	}
}

func TestViewUnbindPrompt(t *testing.T) {
	entries := []ipc.ListEntry{
		{Placeholder: "@TOKEN_aabbcc@", Kind: "test", Status: "accepted",
			Bindings: []string{"api.example.com"}},
	}
	m := buildModel(entries)
	m.state = stateInput
	m.inputMode = inputModeUnbind
	v := m.View()
	if v == "" {
		t.Fatal("unbind input View() returned empty string")
	}
}

func TestViewDaemonError(t *testing.T) {
	m := buildModel(nil)
	m.fetchErr = fmt.Errorf("connection refused")
	v := m.View()
	if v == "" {
		t.Fatal("View() returned empty string when daemon unreachable")
	}
}
