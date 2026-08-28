package vault_test

// A batch of certificates persists the CA's advanced serial counter once,
// before any certificate carrying a reserved number is written. That needs
// the numbers drawn ahead of signing -- ReserveSerials -- and a signing
// entry point that takes an already-drawn number instead of moving the
// counter itself -- SignWithSerial. The counter also outgrew its parser:
// serials cap at 2^159, but the stored value was read back through a
// 64-bit integer, so a CA whose counter passed 2^63 stopped parsing.

import (
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// serialCap mirrors the 2^159 ceiling safe keeps serial numbers under.
func serialCap() *big.Int {
	return new(big.Int).Exp(big.NewInt(2), big.NewInt(159), nil)
}

// Reserving four serials draws four distinct increasing numbers and leaves
// the counter on the last one, so persisting the CA once accounts for the
// whole batch.
func TestReserveSerialsDrawsDistinctIncreasingNumbers(t *testing.T) {
	ca := caNamed(t, "reserve")
	before := new(big.Int).Set(ca.Serial)

	serials := ca.ReserveSerials(4)
	if len(serials) != 4 {
		t.Fatalf("reserved %d serials, want 4", len(serials))
	}
	prev := before
	for i, serial := range serials {
		if serial.Cmp(prev) <= 0 {
			t.Errorf("serial %d is %s, want above %s", i, serial, prev)
		}
		prev = serial
	}
	if ca.Serial.Cmp(serials[3]) != 0 {
		t.Errorf("the counter rests at %s, want the last reserved serial %s", ca.Serial, serials[3])
	}
}

// The counter wraps at the serial ceiling, and the wrap passes over zero:
// RFC 5280 does not allow a zero serial, and a revocation entry could
// never name a certificate carrying one.
func TestReserveSerialsSkipsZeroAcrossTheWrap(t *testing.T) {
	ca := caNamed(t, "wrap")
	ca.Serial = new(big.Int).Sub(serialCap(), big.NewInt(2))

	serials := ca.ReserveSerials(4)

	seen := map[string]bool{}
	for i, serial := range serials {
		if serial.Sign() == 0 {
			t.Errorf("serial %d is zero", i)
		}
		text := serial.Text(16)
		if seen[text] {
			t.Errorf("serial %s was reserved twice", text)
		}
		seen[text] = true
	}
	if want := new(big.Int).Sub(serialCap(), big.NewInt(1)); serials[0].Cmp(want) != 0 {
		t.Errorf("first serial is %s, want %s", serials[0], want)
	}
	if want := big.NewInt(1); serials[1].Cmp(want) != 0 {
		t.Errorf("the serial after the wrap is %s, want 1 (zero skipped)", serials[1])
	}
}

// Signing with a reserved serial stamps that number on the certificate and
// leaves the counter where the reservation put it: the draw already
// happened.
func TestSignWithSerialLeavesTheCounterAlone(t *testing.T) {
	ca := caNamed(t, "presigned")
	reserved := ca.ReserveSerials(1)[0]
	counter := new(big.Int).Set(ca.Serial)

	leaf, err := vault.NewCertificate("CN=leaf", []string{"leaf"},
		[]string{"server_auth"}, "", vault.KeySpec{Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	if err := ca.SignWithSerial(leaf, time.Hour, reserved); err != nil {
		t.Fatalf("SignWithSerial: %v", err)
	}

	if got := derSerial(t, leaf); got.Cmp(reserved) != 0 {
		t.Errorf("the certificate carries serial %s, want the reserved %s", got, reserved)
	}
	if ca.Serial.Cmp(counter) != 0 {
		t.Errorf("the counter moved from %s to %s during signing", counter, ca.Serial)
	}
}

// Sign still draws from the counter itself, one serial per certificate, so
// its callers are untouched by the reservation split.
func TestSignStillAdvancesTheCounter(t *testing.T) {
	ca := caNamed(t, "advance")
	before := new(big.Int).Set(ca.Serial)

	leaf := leafSignedBy(t, ca)

	want := new(big.Int).Add(before, big.NewInt(1))
	if ca.Serial.Cmp(want) != 0 {
		t.Errorf("the counter rests at %s after one signing, want %s", ca.Serial, want)
	}
	if got := derSerial(t, leaf); got.Cmp(want) != 0 {
		t.Errorf("the certificate carries serial %s, want %s", got, want)
	}
}

// A counter that has passed 2^63 still round-trips through the stored
// secret. It used to be read back through a 64-bit parse, which refused
// any value the hex text could no longer fit into one.
func TestABigSerialRoundTripsThroughTheSecret(t *testing.T) {
	ca := caNamed(t, "big-serial")
	want, ok := new(big.Int).SetString("1ffffffffffffffffffff", 16)
	if !ok {
		t.Fatal("building the oversized serial")
	}
	ca.Serial = new(big.Int).Set(want)

	s, err := ca.Secret(false)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	parsed, err := s.X509(true)
	if err != nil {
		t.Fatalf("X509: %v", err)
	}
	if parsed.Serial.Cmp(want) != 0 {
		t.Errorf("the serial came back as %s, want %s", parsed.Serial, want)
	}
}

// Widening the parse does not soften it: a serial that is not hex at all
// still refuses.
func TestAMalformedSerialStillRefusesToParse(t *testing.T) {
	ca := caNamed(t, "malformed")
	s, err := ca.Secret(false)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if err := s.Set("serial", "banana", false); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, err := s.X509(true); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("X509 over a malformed serial = %v, want the malformed-serial refusal", err)
	}
}
