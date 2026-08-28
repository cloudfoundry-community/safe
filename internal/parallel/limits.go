package parallel

import (
	"os"
	"runtime"
	"strconv"
)

// ioLimitDefault flattens realistic path counts in one dispatch round while
// staying well under the transport's MaxIdleConnsPerHost of 100 and a
// loaded Vault's tolerance, and bounds the stragglers a fail-fast run must
// still wait on at 15.
const ioLimitDefault = 16

// IOLimit returns the fan-out width for network-bound work (gets, writes,
// imports, tree deletes and copies), where round-trip latency, not cores,
// is the constraint. SAFE_CONCURRENCY overrides the default, clamped to
// [1, 64]; an unset or unparseable value falls back to the default.
func IOLimit() int {
	if n, err := strconv.Atoi(os.Getenv("SAFE_CONCURRENCY")); err == nil {
		return min(max(n, 1), 64)
	}
	return ioLimitDefault
}

// CPULimit returns the fan-out width for compute-bound work (RSA and SSH
// key generation): one worker per core, with a floor of 4 so small boxes
// still overlap generation with Vault round trips.
func CPULimit() int {
	return max(runtime.NumCPU(), 4)
}
