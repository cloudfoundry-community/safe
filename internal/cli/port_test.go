package cli

import (
	"fmt"
	"net"
	"testing"
)

func TestFindCandidatePortSkipsAHeldPort(t *testing.T) {
	// Hold a port inside the scan range, then scan starting exactly there:
	// the probe must move past it, not report it free.
	held, err := findCandidatePort(localPortScanStart)
	if err != nil {
		t.Fatalf("finding a port to hold: %v", err)
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", held))
	if err != nil {
		t.Fatalf("holding port %d: %v", held, err)
	}
	defer func() { _ = l.Close() }()

	got, err := findCandidatePort(held)
	if err != nil {
		t.Fatalf("findCandidatePort: %v", err)
	}
	if got == held {
		t.Errorf("probe reported held port %d as free", held)
	}
	if got < held {
		t.Errorf("probe went backwards: start %d, got %d", held, got)
	}
}

func TestFindCandidatePortReturnsABindablePort(t *testing.T) {
	got, err := findCandidatePort(localPortScanStart)
	if err != nil {
		t.Fatalf("findCandidatePort: %v", err)
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", got))
	if err != nil {
		t.Errorf("reported port %d cannot be bound: %v", got, err)
	} else {
		_ = l.Close()
	}
}

func TestIsAddrInUse(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{
			"vault and bao on unix",
			"Error parsing listener configuration.\nError initializing listener of type tcp: listen tcp 127.0.0.1:8201: bind: address already in use",
			true,
		},
		{
			"windows socket error",
			"Error initializing listener of type tcp: listen tcp 127.0.0.1:8201: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.",
			true,
		},
		{
			"bad config is not a port collision",
			"Error parsing listener configuration.\nError initializing listener of type tcp: no such file or directory",
			false,
		},
		{
			"address-in-use elsewhere in the log is not the listener failing",
			"[INFO] core: address already in use reported by peer",
			false,
		},
		{"empty output", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAddrInUse(tc.output); got != tc.want {
				t.Errorf("isAddrInUse(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}
}
