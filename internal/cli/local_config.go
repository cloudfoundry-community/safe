package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
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
	port        int      // listener port
	clusterPort int      // raft cluster listener port; 0 means port+1
	memory      bool     // true for an in-memory backend
	filePath    string   // file backend path (when memory is false)
	raftPath    string   // raft backend path (single-node integrated storage)
	engineName  string   // Engine.Name() of the server this config is for
	global      []string // raw key=value overrides for the top-level config
	listener    []string // raw key=value overrides for the listener "tcp" stanza
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

	if p.raftPath != "" {
		// A single-node raft server still needs to know how to reach
		// itself. The cluster listener binds the cluster port on loopback,
		// and cluster_addr advertises it with https because cluster traffic
		// is always TLS. Without an explicit port it sits one above the API
		// port, which is where the engine's own default puts it.
		clusterPort := localClusterPort(p.port, p.clusterPort)
		globalDefaults = append(globalDefaults,
			hclField{key: "api_addr", val: strconv.Quote(fmt.Sprintf("http://127.0.0.1:%d", p.port))},
			hclField{key: "cluster_addr", val: strconv.Quote(fmt.Sprintf("https://127.0.0.1:%d", clusterPort))})
		listenerDefaults = append(listenerDefaults,
			hclField{key: "cluster_address", val: strconv.Quote(fmt.Sprintf("127.0.0.1:%d", clusterPort))})
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

	switch {
	case p.memory:
		b.WriteString("storage \"inmem\" {}\n")
	case p.raftPath != "":
		fmt.Fprintf(&b, "storage \"raft\" {\n  path = %s\n  node_id = %s\n}\n",
			strconv.Quote(p.raftPath), strconv.Quote(raftNodeID))
	default:
		fmt.Fprintf(&b, "storage \"file\" { path = %s }\n", strconv.Quote(p.filePath))
	}

	return b.String(), nil
}

// localClusterPort is the raft cluster port for a server listening on port:
// the explicit --cluster-port when one was given, and otherwise the port
// above the API port.
func localClusterPort(port, explicit int) int {
	if explicit != 0 {
		return explicit
	}
	return port + 1
}

// raftNodeID is the fixed node identity of the single-node raft cluster that
// `safe local --raft` runs. It is a stable contract: a raft store remembers
// its node ID, and ocfp writes this same value when it migrates a file-backed
// vault to raft, so a migrated store finds itself in its own configuration.
// Changing it would leave every existing --raft directory unable to elect a
// leader.
const raftNodeID = "safe-local"

// localDataInitialized reports whether the storage directory already holds a
// vault. The file backend is judged by whether its path exists. Raft is
// judged by what raft writes (vault.db or a raft/ directory), because safe
// creates the raft directory itself before the server starts.
func localDataInitialized(filePath, raftPath string) bool {
	if raftPath != "" {
		for _, name := range []string{"vault.db", "raft"} {
			if _, err := os.Stat(filepath.Join(raftPath, name)); err == nil {
				return true
			}
		}
		return false
	}
	if filePath == "" {
		return false
	}
	_, err := os.Stat(filePath)
	return err == nil || !os.IsNotExist(err)
}

// ensureRaftDir creates the raft data directory (mode 0700) when it is new.
// Raft will not create it, and an existing directory is left as it is.
func ensureRaftDir(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("--raft path %q exists and is not a directory", path)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(path, 0o700)
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
