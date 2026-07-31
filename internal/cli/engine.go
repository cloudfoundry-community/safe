package cli

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
)

// Engine is a Vault-compatible server binary that safe can drive: HashiCorp
// Vault, or OpenBao, which forked from it and keeps the same server, secrets,
// auth, and operator command surface.
type Engine interface {
	// Name is the engine's canonical short name, as accepted by --engine.
	Name() string
	// Binary is the absolute path to the resolved executable.
	Binary() string
}

type engine struct {
	name   string
	binary string
}

func (e *engine) Name() string   { return e.name }
func (e *engine) Binary() string { return e.binary }

// engineNames is the resolution order used when nothing pins an engine. Vault
// comes first so that installing OpenBao alongside an existing Vault does not
// silently change which server `safe local` starts. Set SAFE_ENGINE=bao (or
// pass --engine bao) to invert it.
var engineNames = []string{"vault", "bao"}

// EngineEnvVar names the environment variable that sets a default engine
// preference, for users who want OpenBao without passing --engine every time.
const EngineEnvVar = "SAFE_ENGINE"

func knownEngine(name string) bool {
	return slices.Contains(engineNames, name)
}

// selectEngine resolves which server binary to run. A non-empty preference
// (from --engine) wins; otherwise SAFE_ENGINE is consulted; otherwise the
// first engine found on $PATH in engineNames order is used.
//
// A pinned engine is never silently substituted: if it is not on $PATH, that
// is an error rather than a fallback, so a script asking for one engine cannot
// end up talking to the other.
func selectEngine(preference string) (Engine, error) {
	source := "--engine"
	preference = strings.ToLower(strings.TrimSpace(preference))
	if preference == "" {
		source = EngineEnvVar
		preference = strings.ToLower(strings.TrimSpace(os.Getenv(EngineEnvVar)))
	}

	if preference != "" && !knownEngine(preference) {
		return nil, fmt.Errorf("unknown engine %q from %s (supported by --engine and %s: %s)",
			preference, source, EngineEnvVar, strings.Join(engineNames, ", "))
	}

	order := engineNames
	if preference != "" {
		order = []string{preference}
	}

	for _, name := range order {
		// LookPath reports ErrDot for a match found through a relative
		// $PATH entry; skipping it like any other miss keeps Binary()
		// absolute and never runs a binary picked up from a relative dir.
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		return &engine{name: name, binary: path}, nil
	}

	if preference != "" {
		return nil, fmt.Errorf("%s is not installed or located in $PATH", preference)
	}
	return nil, fmt.Errorf("neither %s is installed or located in $PATH",
		strings.Join(engineNames, " nor "))
}
