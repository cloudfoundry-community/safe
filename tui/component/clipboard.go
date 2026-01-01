package component

import (
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
)

// ClipboardContent represents what type of content was copied
type ClipboardContent int

const (
	ClipboardValue ClipboardContent = iota
	ClipboardPath
	ClipboardKey
	ClipboardSecret // Full secret as JSON/YAML
)

// ClipboardCopyMsg requests copying content to clipboard
type ClipboardCopyMsg struct {
	Content     string
	ContentType ClipboardContent
	Path        string // Original path for reference
	Key         string // Original key for reference
}

// ClipboardCopiedMsg is sent when content is copied successfully
type ClipboardCopiedMsg struct {
	ContentType ClipboardContent
	Path        string
	Key         string
	Success     bool
	Error       error
}

// ClipboardPasteMsg requests pasting from clipboard
type ClipboardPasteMsg struct{}

// ClipboardPastedMsg is sent when content is pasted
type ClipboardPastedMsg struct {
	Content string
	Success bool
	Error   error
}

// ClipboardClearMsg requests clearing the clipboard after a timeout
type ClipboardClearMsg struct {
	Timeout time.Duration
}

// ClipboardClearedMsg is sent when clipboard is cleared
type ClipboardClearedMsg struct{}

// ClipboardUnavailableMsg is sent when clipboard is not available
type ClipboardUnavailableMsg struct {
	Error error
}

// CopyToClipboard copies content to the system clipboard
func CopyToClipboard(content string, contentType ClipboardContent, path, key string) tea.Cmd {
	return func() tea.Msg {
		err := clipboard.WriteAll(content)
		if err != nil {
			return ClipboardCopiedMsg{
				ContentType: contentType,
				Path:        path,
				Key:         key,
				Success:     false,
				Error:       err,
			}
		}

		return ClipboardCopiedMsg{
			ContentType: contentType,
			Path:        path,
			Key:         key,
			Success:     true,
		}
	}
}

// CopySecretValue copies a secret value to clipboard
func CopySecretValue(value, path, key string) tea.Cmd {
	return CopyToClipboard(value, ClipboardValue, path, key)
}

// CopyPath copies a path to clipboard
func CopyPath(path string) tea.Cmd {
	return CopyToClipboard(path, ClipboardPath, path, "")
}

// CopyKey copies a key name to clipboard
func CopyKey(key, path string) tea.Cmd {
	return CopyToClipboard(key, ClipboardKey, path, key)
}

// PasteFromClipboard pastes content from the system clipboard
func PasteFromClipboard() tea.Cmd {
	return func() tea.Msg {
		content, err := clipboard.ReadAll()
		if err != nil {
			return ClipboardPastedMsg{
				Success: false,
				Error:   err,
			}
		}

		return ClipboardPastedMsg{
			Content: content,
			Success: true,
		}
	}
}

// ClearClipboardAfter clears the clipboard after a timeout
func ClearClipboardAfter(timeout time.Duration) tea.Cmd {
	return tea.Tick(timeout, func(t time.Time) tea.Msg {
		_ = clipboard.WriteAll("")
		return ClipboardClearedMsg{}
	})
}

// IsClipboardAvailable checks if clipboard is available
func IsClipboardAvailable() bool {
	// Try to read from clipboard to check availability
	_, err := clipboard.ReadAll()
	return err == nil
}

// GetClipboardMessage returns a user-friendly message for clipboard operations
func GetClipboardMessage(msg ClipboardCopiedMsg) string {
	if !msg.Success {
		if msg.Error != nil {
			return "Failed to copy: " + msg.Error.Error()
		}
		return "Failed to copy to clipboard"
	}

	switch msg.ContentType {
	case ClipboardValue:
		if msg.Key != "" {
			return "Copied value of '" + msg.Key + "' to clipboard"
		}
		return "Copied value to clipboard"
	case ClipboardPath:
		return "Copied path to clipboard"
	case ClipboardKey:
		return "Copied key name to clipboard"
	case ClipboardSecret:
		return "Copied secret to clipboard"
	default:
		return "Copied to clipboard"
	}
}

// Clipboard wraps clipboard functionality with state tracking
type Clipboard struct {
	lastCopied   string
	lastCopyType ClipboardContent
	lastCopyPath string
	lastCopyKey  string
	lastCopyTime time.Time
	clearTimeout time.Duration
	autoClear    bool
}

// NewClipboard creates a new clipboard wrapper
func NewClipboard() Clipboard {
	return Clipboard{
		clearTimeout: 30 * time.Second,
		autoClear:    false, // Disabled by default for safety
	}
}

// Copy copies content to clipboard and tracks it
func (c *Clipboard) Copy(content string, contentType ClipboardContent, path, key string) tea.Cmd {
	c.lastCopied = content
	c.lastCopyType = contentType
	c.lastCopyPath = path
	c.lastCopyKey = key
	c.lastCopyTime = time.Now()

	cmd := CopyToClipboard(content, contentType, path, key)

	if c.autoClear && c.clearTimeout > 0 {
		return tea.Batch(cmd, ClearClipboardAfter(c.clearTimeout))
	}

	return cmd
}

// CopyValue copies a secret value
func (c *Clipboard) CopyValue(value, path, key string) tea.Cmd {
	return c.Copy(value, ClipboardValue, path, key)
}

// CopyPath copies a path
func (c *Clipboard) CopyPath(path string) tea.Cmd {
	return c.Copy(path, ClipboardPath, path, "")
}

// SetAutoClear enables/disables auto-clearing of sensitive data
func (c *Clipboard) SetAutoClear(enabled bool) {
	c.autoClear = enabled
}

// SetClearTimeout sets the auto-clear timeout
func (c *Clipboard) SetClearTimeout(timeout time.Duration) {
	c.clearTimeout = timeout
}

// LastCopiedType returns the type of the last copied content
func (c *Clipboard) LastCopiedType() ClipboardContent {
	return c.lastCopyType
}

// LastCopiedPath returns the path of the last copied content
func (c *Clipboard) LastCopiedPath() string {
	return c.lastCopyPath
}

// TimeSinceLastCopy returns the time since the last copy operation
func (c *Clipboard) TimeSinceLastCopy() time.Duration {
	if c.lastCopyTime.IsZero() {
		return 0
	}
	return time.Since(c.lastCopyTime)
}
