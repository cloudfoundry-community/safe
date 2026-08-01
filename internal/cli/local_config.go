package cli

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// hclField is a single rendered "key = value" line in the server config that
// `safe local` writes. val is already an HCL literal (bare number/bool or a
// quoted string).
type hclField struct {
	key string
	val string
}

// localConfigParams carries everything needed to render the HCL config for
// `safe local`.
type localConfigParams struct {
	port       int      // listener port
	memory     bool     // true for an in-memory backend
	filePath   string   // file backend path (when memory is false)
	engineName string   // Engine.Name() of the server this config is for
	global     []string // raw key=value overrides for the top-level config
	listener   []string // raw key=value overrides for the listener "tcp" stanza
}

// hclKeyPattern matches a bare HCL identifier usable as a config key.
var hclKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// parseConfigKV splits a "key=value" CLI argument into its key and raw value.
// Only the first '=' splits, so values may themselves contain '='. The key
// must be a valid HCL identifier; the value is returned verbatim (trimmed) for
// renderHCLValue to type. Any deeper validity is left to Vault.
func parseConfigKV(pair string) (key, value string, err error) {
	rawKey, rawValue, found := strings.Cut(pair, "=")
	if !found {
		return "", "", fmt.Errorf("invalid key/value pair %q: expected key=value", pair)
	}
	key = strings.TrimSpace(rawKey)
	value = strings.TrimSpace(rawValue)
	if key == "" {
		return "", "", fmt.Errorf("invalid key/value pair %q: empty key", pair)
	}
	if !hclKeyPattern.MatchString(key) {
		return "", "", fmt.Errorf("invalid config key %q: must match %s", key, hclKeyPattern.String())
	}
	return key, value, nil
}

// renderHCLValue infers the HCL literal form of a raw CLI value: integers,
// floats, and booleans are emitted bare; everything else is quoted as a
// string. A value already wrapped in double quotes passes through unchanged so
// callers can force string typing.
func renderHCLValue(raw string) string {
	if len(raw) >= 2 && strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) {
		return raw
	}
	if raw == "true" || raw == "false" {
		return raw
	}
	if _, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return raw
	}
	if _, err := strconv.ParseFloat(raw, 64); err == nil {
		return raw
	}
	return strconv.Quote(raw)
}

// applyConfigKV overlays raw "key=value" CLI arguments onto a copy of the
// default fields. An override whose key matches a default replaces that field's
// value in place; a new key is appended, keeping deterministic ordering. The
// caller's defaults slice is never mutated.
func applyConfigKV(defaults []hclField, pairs []string) ([]hclField, error) {
	fields := make([]hclField, len(defaults))
	copy(fields, defaults)

	for _, pair := range pairs {
		key, value, err := parseConfigKV(pair)
		if err != nil {
			return nil, err
		}
		rendered := renderHCLValue(value)

		replaced := false
		for i := range fields {
			if fields[i].key == key {
				fields[i].val = rendered
				replaced = true
				break
			}
		}
		if !replaced {
			fields = append(fields, hclField{key: key, val: rendered})
		}
	}
	return fields, nil
}

// buildLocalConfig renders the HCL config for `safe local`, layering any
// user-supplied global and listener overrides on top of safe's defaults. It
// only type-checks the overrides; an invalid config value is the server's
// problem to report, and its error is surfaced when it fails to start.
func buildLocalConfig(p localConfigParams) (string, error) {
	// The default fields diverge per engine. OpenBao removed mlock support,
	// so its config drops disable_mlock (the key only draws an "unknown
	// field" warning there). It also ships with the /sys/rekey/* endpoints
	// disabled (since 2.5.0), which would leave `safe rekey` facing 405s
	// from the very server safe started, so the listener opts back in.
	// Either default can still be overridden from the command line.
	globalDefaults := []hclField{
		{key: "disable_mlock", val: "true"},
	}
	listenerDefaults := []hclField{
		{key: "address", val: strconv.Quote(fmt.Sprintf("127.0.0.1:%d", p.port))},
		{key: "tls_disable", val: "1"},
	}
	if p.engineName == "bao" {
		globalDefaults = nil
		listenerDefaults = append(listenerDefaults,
			hclField{key: "disable_unauthed_rekey_endpoints", val: "false"})
	}

	global, err := applyConfigKV(globalDefaults, p.global)
	if err != nil {
		return "", err
	}

	listener, err := applyConfigKV(listenerDefaults, p.listener)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("# safe local config\n")
	for _, f := range global {
		fmt.Fprintf(&b, "%s = %s\n", f.key, f.val)
	}

	b.WriteString("\nlistener \"tcp\" {\n")
	for _, f := range listener {
		fmt.Fprintf(&b, "  %s = %s\n", f.key, f.val)
	}
	b.WriteString("}\n")

	if p.memory {
		b.WriteString("storage \"inmem\" {}\n")
	} else {
		fmt.Fprintf(&b, "storage \"file\" { path = %s }\n", strconv.Quote(p.filePath))
	}

	return b.String(), nil
}

// lockedBuffer is a goroutine-safe byte sink. `safe local` points the server
// process's stderr at one so its output can be read for an error message while
// the copying goroutine may still be writing to it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// isAddrInUse reports whether the server's output says its listener failed
// because the address was taken -- the one startup failure it is correct to
// retry on another port. Both engines print an "Error initializing listener"
// line whose cause is the OS bind error: "address already in use" on unix,
// "only one usage of each socket address" on Windows. An address-in-use
// phrase anywhere else in the log is not the listener failing.
func isAddrInUse(output string) bool {
	lower := strings.ToLower(output)
	idx := strings.Index(lower, "error initializing listener")
	if idx < 0 {
		return false
	}
	rest := lower[idx:]
	return strings.Contains(rest, "address already in use") ||
		strings.Contains(rest, "only one usage of each socket address")
}

// engineStartupError explains why the local server failed to start, preferring
// the engine's own stderr output and falling back to the process wait error.
func engineStartupError(stderr string, waitErr error) string {
	if msg := strings.TrimSpace(stderr); msg != "" {
		return msg
	}
	if waitErr != nil {
		return waitErr.Error()
	}
	return "exited without output"
}
