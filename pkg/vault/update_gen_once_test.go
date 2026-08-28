package vault_test

// The keygen-family commands hoist generation out of Update's retry loop:
// material is generated at most once per target, on the first attempt
// that needs it, and a conflict retry re-installs the same material
// against fresh state instead of paying openssl-minutes or keygen-seconds
// again. The command closures in internal/cli cannot reach this package's
// generator seams (export_test.go is only visible from vault_test), so
// the once-per-target contract is pinned here, driving Update with the
// same lazy-once closure shape the commands use; internal/cli's own tests
// assert request budgets and on-the-wire material equality instead.

import (
	"context"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// A conflict retry must not run openssl dhparam again: the first
// attempt's material is installed verbatim on the retry, and the
// concurrent writer's key survives beside it.
func TestUpdateRetryGeneratesDHParamsOnce(t *testing.T) {
	calls := 0
	restore := vault.SetDhparamGenForTest(func(ctx context.Context, bits int) (string, error) {
		calls++
		return "FAKE-DHPARAM-PEM", nil
	})
	t.Cleanup(restore)

	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"other": "x"})
	fv.afterRequest(updDataGet, 1, func() {
		fv.setV2(updDataPath, map[string]string{"other": "x", "theirs": "y"})
	})

	var material string
	_, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if material == "" {
			if err := s.DHParamContext(context.Background(), 1024, false); err != nil {
				return nil, false, err
			}
			material = s.Get("dhparam-pem")
			return nil, true, nil
		}
		if err := s.Set("dhparam-pem", material, false); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if calls != 1 {
		t.Errorf("dhparam generator ran %d times across the conflict retry, want exactly 1", calls)
	}

	got := latestV2Data(t, fv, updDataPath)
	if got["dhparam-pem"] != "FAKE-DHPARAM-PEM" || got["theirs"] != "y" || got["other"] != "x" {
		t.Errorf("final secret = %v, want the once-generated material beside both concurrent keys", got)
	}
}

// Same contract for SSH keypairs: seconds of rsa.GenerateKey happen once,
// and the retry re-installs the identical keypair.
func TestUpdateRetryGeneratesSSHKeyOnce(t *testing.T) {
	calls := 0
	restore := vault.SetSSHKeyGenForTest(func(bits int) (string, string, string, error) {
		calls++
		return "FAKE-PRIVATE", "FAKE-PUBLIC", "FAKE-FINGERPRINT", nil
	})
	t.Cleanup(restore)

	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"other": "x"})
	fv.afterRequest(updDataGet, 1, func() {
		fv.setV2(updDataPath, map[string]string{"other": "x", "theirs": "y"})
	})

	var material *vault.Secret
	_, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if material == nil {
			scratch := vault.NewSecret()
			if err := scratch.SSHKey(1024, false); err != nil {
				return nil, false, err
			}
			material = scratch
		}
		for _, k := range material.Keys() {
			if err := s.Set(k, material.Get(k), false); err != nil {
				return nil, false, err
			}
		}
		return nil, true, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if calls != 1 {
		t.Errorf("SSH key generator ran %d times across the conflict retry, want exactly 1", calls)
	}

	got := latestV2Data(t, fv, updDataPath)
	if got["private"] != "FAKE-PRIVATE" || got["fingerprint"] != "FAKE-FINGERPRINT" || got["theirs"] != "y" {
		t.Errorf("final secret = %v, want the once-generated keypair beside the concurrent key", got)
	}
}
