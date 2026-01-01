package component

import (
	"errors"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ErrorType categorizes errors for appropriate handling
type ErrorType int

const (
	ErrorTypeGeneral ErrorType = iota
	ErrorTypeConnection
	ErrorTypeAuthentication
	ErrorTypePermission
	ErrorTypeNotFound
	ErrorTypeValidation
	ErrorTypeTimeout
	ErrorTypeNetwork
	ErrorTypeVaultSealed
	ErrorTypeRateLimited
)

// SafeError wraps an error with additional context
type SafeError struct {
	Original    error
	Type        ErrorType
	Message     string
	Detail      string
	Retryable   bool
	Suggestions []string
	Timestamp   time.Time
}

// NewSafeError creates a new SafeError from a regular error
func NewSafeError(err error) *SafeError {
	if err == nil {
		return nil
	}

	se := &SafeError{
		Original:  err,
		Type:      ErrorTypeGeneral,
		Message:   err.Error(),
		Timestamp: time.Now(),
	}

	// Analyze error and set type/suggestions
	se.analyze()

	return se
}

// Error implements the error interface
func (e *SafeError) Error() string {
	return e.Message
}

// Unwrap returns the original error
func (e *SafeError) Unwrap() error {
	return e.Original
}

// analyze categorizes the error and sets suggestions
func (e *SafeError) analyze() {
	msg := strings.ToLower(e.Original.Error())

	switch {
	case strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "network is unreachable"):
		e.Type = ErrorTypeNetwork
		e.Message = "Unable to connect to Vault server"
		e.Retryable = true
		e.Suggestions = []string{
			"Check that the Vault server is running",
			"Verify the Vault address in your configuration",
			"Check your network connection",
		}

	case strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe"):
		e.Type = ErrorTypeConnection
		e.Message = "Connection to Vault was interrupted"
		e.Retryable = true
		e.Suggestions = []string{
			"Try reconnecting to the Vault",
			"Check network stability",
		}

	case strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "403"):
		e.Type = ErrorTypePermission
		e.Message = "Permission denied"
		e.Retryable = false
		e.Suggestions = []string{
			"Check that your token has the required permissions",
			"Verify the ACL policy allows this operation",
			"Try re-authenticating with appropriate credentials",
		}

	case strings.Contains(msg, "not found") ||
		strings.Contains(msg, "404") ||
		strings.Contains(msg, "no such"):
		e.Type = ErrorTypeNotFound
		e.Message = "Resource not found"
		e.Retryable = false
		e.Suggestions = []string{
			"Verify the path is correct",
			"Check if the secret exists",
		}

	case strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "401") ||
		strings.Contains(msg, "authentication"):
		e.Type = ErrorTypeAuthentication
		e.Message = "Authentication failed"
		e.Retryable = false
		e.Suggestions = []string{
			"Your token may have expired",
			"Try running 'safe auth' to re-authenticate",
			"Check your token permissions",
		}

	case strings.Contains(msg, "sealed") ||
		strings.Contains(msg, "standby"):
		e.Type = ErrorTypeVaultSealed
		e.Message = "Vault is sealed or in standby mode"
		e.Retryable = false
		e.Suggestions = []string{
			"The Vault needs to be unsealed before use",
			"Use the Admin panel (Ctrl+A) to unseal",
			"Contact your Vault administrator",
		}

	case strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded"):
		e.Type = ErrorTypeTimeout
		e.Message = "Operation timed out"
		e.Retryable = true
		e.Suggestions = []string{
			"The server may be overloaded",
			"Try the operation again",
			"Check network latency",
		}

	case strings.Contains(msg, "rate limit") ||
		strings.Contains(msg, "429") ||
		strings.Contains(msg, "too many requests"):
		e.Type = ErrorTypeRateLimited
		e.Message = "Rate limit exceeded"
		e.Retryable = true
		e.Suggestions = []string{
			"Wait a moment before retrying",
			"Reduce the frequency of requests",
		}

	case strings.Contains(msg, "invalid") ||
		strings.Contains(msg, "validation"):
		e.Type = ErrorTypeValidation
		e.Message = "Validation error"
		e.Retryable = false
		e.Suggestions = []string{
			"Check the input values",
			"Ensure all required fields are provided",
		}
	}
}

// WithDetail adds detail to the error
func (e *SafeError) WithDetail(detail string) *SafeError {
	e.Detail = detail
	return e
}

// WithSuggestion adds a suggestion
func (e *SafeError) WithSuggestion(suggestion string) *SafeError {
	e.Suggestions = append(e.Suggestions, suggestion)
	return e
}

// ErrorStyles contains styles for error display
type ErrorStyles struct {
	ErrorIcon        lipgloss.Style
	ErrorMessage     lipgloss.Style
	ErrorDetail      lipgloss.Style
	Suggestion       lipgloss.Style
	SuggestionBullet lipgloss.Style
	Retry            lipgloss.Style
}

// DefaultErrorStyles returns the default error styles
func DefaultErrorStyles() ErrorStyles {
	return ErrorStyles{
		ErrorIcon: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")).
			Bold(true),

		ErrorMessage: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")),

		ErrorDetail: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF")).
			Italic(true),

		Suggestion: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6ADC8")),

		SuggestionBullet: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89B4FA")),

		Retry: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1")),
	}
}

// FormatError formats an error for display
func FormatError(err error) string {
	styles := DefaultErrorStyles()
	return FormatErrorWithStyles(err, styles)
}

// FormatErrorWithStyles formats an error with custom styles
func FormatErrorWithStyles(err error, styles ErrorStyles) string {
	if err == nil {
		return ""
	}

	var se *SafeError
	if errors.As(err, &se) {
		return formatSafeError(se, styles)
	}

	// Wrap and format as SafeError
	se = NewSafeError(err)
	return formatSafeError(se, styles)
}

// formatSafeError formats a SafeError for display
func formatSafeError(se *SafeError, styles ErrorStyles) string {
	var s strings.Builder

	// Error icon and message
	icon := getErrorIcon(se.Type)
	s.WriteString(styles.ErrorIcon.Render(icon))
	s.WriteString(" ")
	s.WriteString(styles.ErrorMessage.Render(se.Message))
	s.WriteString("\n")

	// Detail if present
	if se.Detail != "" {
		s.WriteString("  ")
		s.WriteString(styles.ErrorDetail.Render(se.Detail))
		s.WriteString("\n")
	}

	// Suggestions
	if len(se.Suggestions) > 0 {
		s.WriteString("\n")
		for _, suggestion := range se.Suggestions {
			s.WriteString("  ")
			s.WriteString(styles.SuggestionBullet.Render("  "))
			s.WriteString(styles.Suggestion.Render(suggestion))
			s.WriteString("\n")
		}
	}

	// Retry hint
	if se.Retryable {
		s.WriteString("\n")
		s.WriteString(styles.Retry.Render("  This error may be temporary. Try again."))
		s.WriteString("\n")
	}

	return s.String()
}

// getErrorIcon returns an icon for the error type
func getErrorIcon(t ErrorType) string {
	switch t {
	case ErrorTypeNetwork:
		return "[Network Error]"
	case ErrorTypeConnection:
		return "[Connection Error]"
	case ErrorTypeAuthentication:
		return "[Auth Error]"
	case ErrorTypePermission:
		return "[Permission Error]"
	case ErrorTypeNotFound:
		return "[Not Found]"
	case ErrorTypeTimeout:
		return "[Timeout]"
	case ErrorTypeVaultSealed:
		return "[Vault Sealed]"
	case ErrorTypeRateLimited:
		return "[Rate Limited]"
	case ErrorTypeValidation:
		return "[Validation Error]"
	default:
		return "[Error]"
	}
}

// FormatErrorCompact formats an error for compact display (e.g., status bar)
func FormatErrorCompact(err error) string {
	if err == nil {
		return ""
	}

	var se *SafeError
	if errors.As(err, &se) {
		return se.Message
	}

	// Simple analysis for non-SafeError
	se = NewSafeError(err)
	return se.Message
}

// FormatErrorWithRetry formats an error with retry information
func FormatErrorWithRetry(err error, canRetry bool, retryKey string) string {
	result := FormatError(err)
	if canRetry && retryKey != "" {
		styles := DefaultErrorStyles()
		result += "\n" + styles.Retry.Render("Press "+retryKey+" to retry")
	}
	return result
}

// ErrorBanner creates a styled error banner
func ErrorBanner(message string, width int) string {
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#F38BA8")).
		Bold(true).
		Padding(0, 1).
		Width(width).
		Align(lipgloss.Center)

	return style.Render(" " + message)
}

// WarningBanner creates a styled warning banner
func WarningBanner(message string, width int) string {
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#1E1E2E")).
		Background(lipgloss.Color("#F9E2AF")).
		Bold(true).
		Padding(0, 1).
		Width(width).
		Align(lipgloss.Center)

	return style.Render(" " + message)
}

// InfoBanner creates a styled info banner
func InfoBanner(message string, width int) string {
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#89B4FA")).
		Bold(true).
		Padding(0, 1).
		Width(width).
		Align(lipgloss.Center)

	return style.Render("i " + message)
}

// SuccessBanner creates a styled success banner
func SuccessBanner(message string, width int) string {
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#1E1E2E")).
		Background(lipgloss.Color("#A6E3A1")).
		Bold(true).
		Padding(0, 1).
		Width(width).
		Align(lipgloss.Center)

	return style.Render(" " + message)
}

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	var se *SafeError
	if errors.As(err, &se) {
		return se.Retryable
	}

	// Analyze dynamically
	se = NewSafeError(err)
	return se.Retryable
}

// GetErrorType returns the error type for an error
func GetErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeGeneral
	}

	var se *SafeError
	if errors.As(err, &se) {
		return se.Type
	}

	// Analyze dynamically
	se = NewSafeError(err)
	return se.Type
}
