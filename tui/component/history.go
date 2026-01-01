package component

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// EditAction represents a type of edit action
type EditAction int

const (
	ActionCreate EditAction = iota
	ActionUpdate
	ActionDelete
	ActionRename
	ActionMove
)

// HistoryEntry represents a single entry in the edit history
type HistoryEntry struct {
	Action      EditAction
	Path        string
	Key         string            // For key-level operations
	OldValue    string            // Value before the change
	NewValue    string            // Value after the change
	OldData     map[string]string // Full secret data before change (for complex ops)
	NewData     map[string]string // Full secret data after change
	Timestamp   time.Time
	Description string
}

// History manages undo/redo functionality
type History struct {
	entries  []HistoryEntry
	position int // Current position in history (-1 means at latest)
	maxSize  int // Maximum number of history entries
	enabled  bool
}

// NewHistory creates a new history manager
func NewHistory() History {
	return History{
		entries:  make([]HistoryEntry, 0, 100),
		position: -1,
		maxSize:  100,
		enabled:  true,
	}
}

// Record records a new action in history
func (h *History) Record(entry HistoryEntry) {
	if !h.enabled {
		return
	}

	// If we're not at the latest position, discard future history
	if h.position >= 0 && h.position < len(h.entries)-1 {
		h.entries = h.entries[:h.position+1]
	}

	// Set timestamp
	entry.Timestamp = time.Now()

	// Add entry
	h.entries = append(h.entries, entry)

	// Trim if over max size
	if len(h.entries) > h.maxSize {
		h.entries = h.entries[len(h.entries)-h.maxSize:]
	}

	// Reset position to latest
	h.position = len(h.entries) - 1
}

// RecordCreate records a create action
func (h *History) RecordCreate(path string, data map[string]string) {
	h.Record(HistoryEntry{
		Action:      ActionCreate,
		Path:        path,
		NewData:     copyMap(data),
		Description: "Created " + path,
	})
}

// RecordUpdate records an update action
func (h *History) RecordUpdate(path, key, oldValue, newValue string) {
	h.Record(HistoryEntry{
		Action:      ActionUpdate,
		Path:        path,
		Key:         key,
		OldValue:    oldValue,
		NewValue:    newValue,
		Description: "Updated " + key + " in " + path,
	})
}

// RecordUpdateFull records a full secret update
func (h *History) RecordUpdateFull(path string, oldData, newData map[string]string) {
	h.Record(HistoryEntry{
		Action:      ActionUpdate,
		Path:        path,
		OldData:     copyMap(oldData),
		NewData:     copyMap(newData),
		Description: "Updated " + path,
	})
}

// RecordDelete records a delete action
func (h *History) RecordDelete(path string, oldData map[string]string) {
	h.Record(HistoryEntry{
		Action:      ActionDelete,
		Path:        path,
		OldData:     copyMap(oldData),
		Description: "Deleted " + path,
	})
}

// RecordRename records a rename action
func (h *History) RecordRename(oldPath, newPath string, data map[string]string) {
	h.Record(HistoryEntry{
		Action:      ActionRename,
		Path:        newPath,
		OldValue:    oldPath,
		NewValue:    newPath,
		OldData:     copyMap(data),
		Description: "Renamed " + oldPath + " to " + newPath,
	})
}

// RecordMove records a move action
func (h *History) RecordMove(oldPath, newPath string, data map[string]string) {
	h.Record(HistoryEntry{
		Action:      ActionMove,
		Path:        newPath,
		OldValue:    oldPath,
		NewValue:    newPath,
		OldData:     copyMap(data),
		Description: "Moved " + oldPath + " to " + newPath,
	})
}

// CanUndo returns whether an undo operation is possible
func (h *History) CanUndo() bool {
	return len(h.entries) > 0 && h.position >= 0
}

// CanRedo returns whether a redo operation is possible
func (h *History) CanRedo() bool {
	return len(h.entries) > 0 && h.position < len(h.entries)-1
}

// Undo returns the entry to undo and moves the position back
func (h *History) Undo() *HistoryEntry {
	if !h.CanUndo() {
		return nil
	}

	entry := &h.entries[h.position]
	h.position--
	return entry
}

// Redo returns the entry to redo and moves the position forward
func (h *History) Redo() *HistoryEntry {
	if !h.CanRedo() {
		return nil
	}

	h.position++
	return &h.entries[h.position]
}

// PeekUndo returns the entry that would be undone without changing position
func (h *History) PeekUndo() *HistoryEntry {
	if !h.CanUndo() {
		return nil
	}
	return &h.entries[h.position]
}

// PeekRedo returns the entry that would be redone without changing position
func (h *History) PeekRedo() *HistoryEntry {
	if !h.CanRedo() {
		return nil
	}
	return &h.entries[h.position+1]
}

// UndoCount returns the number of undo operations available
func (h *History) UndoCount() int {
	if h.position < 0 {
		return 0
	}
	return h.position + 1
}

// RedoCount returns the number of redo operations available
func (h *History) RedoCount() int {
	if h.position >= len(h.entries)-1 {
		return 0
	}
	return len(h.entries) - h.position - 1
}

// Clear clears all history
func (h *History) Clear() {
	h.entries = h.entries[:0]
	h.position = -1
}

// SetEnabled enables or disables history recording
func (h *History) SetEnabled(enabled bool) {
	h.enabled = enabled
}

// IsEnabled returns whether history recording is enabled
func (h *History) IsEnabled() bool {
	return h.enabled
}

// SetMaxSize sets the maximum number of history entries
func (h *History) SetMaxSize(size int) {
	h.maxSize = size
	// Trim if necessary
	if len(h.entries) > h.maxSize {
		h.entries = h.entries[len(h.entries)-h.maxSize:]
		if h.position >= len(h.entries) {
			h.position = len(h.entries) - 1
		}
	}
}

// Size returns the current number of history entries
func (h *History) Size() int {
	return len(h.entries)
}

// GetStatusText returns a status text for display in status bar
func (h *History) GetStatusText() string {
	if !h.enabled {
		return ""
	}

	undoCount := h.UndoCount()
	redoCount := h.RedoCount()

	if undoCount == 0 && redoCount == 0 {
		return ""
	}

	text := ""
	if undoCount > 0 {
		text += "Undo: " + intToString(undoCount)
	}
	if redoCount > 0 {
		if text != "" {
			text += " | "
		}
		text += "Redo: " + intToString(redoCount)
	}
	return text
}

// intToString converts an int to string without fmt
func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// copyMap creates a copy of a map
func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// Messages

// HistoryUndoMsg requests an undo operation
type HistoryUndoMsg struct{}

// HistoryRedoMsg requests a redo operation
type HistoryRedoMsg struct{}

// HistoryUndoneMsg is sent when an undo operation completes
type HistoryUndoneMsg struct {
	Entry   HistoryEntry
	Success bool
	Error   error
}

// HistoryRedoneMsg is sent when a redo operation completes
type HistoryRedoneMsg struct {
	Entry   HistoryEntry
	Success bool
	Error   error
}

// HistoryRecordMsg requests recording an action
type HistoryRecordMsg struct {
	Entry HistoryEntry
}

// HistoryClearMsg requests clearing history
type HistoryClearMsg struct{}

// UndoCmd returns a command to perform an undo
func UndoCmd() tea.Cmd {
	return func() tea.Msg {
		return HistoryUndoMsg{}
	}
}

// RedoCmd returns a command to perform a redo
func RedoCmd() tea.Cmd {
	return func() tea.Msg {
		return HistoryRedoMsg{}
	}
}
