// ExplainNotFound narrows a not-found error from Read after the fact: when
// the secret exists and only its newest version cannot be read, it says
// which version and what became of it. It must narrow nothing else -- not a
// foreign error, not a versioned path the caller already named, not a
// secret with no history, and not a 404 whose newest version turns out to
// be alive -- because a wrong explanation is worse than none.

package vault_test

import (
	"errors"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func TestExplainNotFoundNamesADeletedLatestVersion(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)
	fv.deleteV2("kv2/app", 2)

	_, err := v.Read("kv2/app")
	assertSecretNotFound(t, err)

	got := v.ExplainNotFound("kv2/app", err)
	want := vault.VersionNotFoundMessage("kv2/app", 2, "deleted")
	if got.Error() != want {
		t.Errorf("explained error = %q, want %q", got, want)
	}
	//The narrowed error keeps its kind: exists, gen, and friends still
	// branch on IsSecretNotFound.
	if !vault.IsSecretNotFound(got) {
		t.Error("the explanation stopped answering to IsSecretNotFound")
	}
}

func TestExplainNotFoundNamesADestroyedLatestVersion(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)
	fv.destroyV2("kv2/app", 2)

	_, err := v.Read("kv2/app")
	assertSecretNotFound(t, err)

	got := v.ExplainNotFound("kv2/app", err)
	want := vault.VersionNotFoundMessage("kv2/app", 2, "destroyed")
	if got.Error() != want {
		t.Errorf("explained error = %q, want %q", got, want)
	}
	if !vault.IsSecretNotFound(got) {
		t.Error("the explanation stopped answering to IsSecretNotFound")
	}
}

// An error that is not a secret-not-found is none of ExplainNotFound's
// business, nil included.
func TestExplainNotFoundLeavesOtherErrorsAlone(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	boom := errors.New("connection refused")
	if got := v.ExplainNotFound("secret/app", boom); got != boom {
		t.Errorf("ExplainNotFound rewrote a foreign error into %q", got)
	}
	if got := v.ExplainNotFound("secret/app", nil); got != nil {
		t.Errorf("ExplainNotFound turned nil into %q", got)
	}
}

// A read that named a version already got the most specific answer there
// is, from notFoundReading; explaining it again could only say less.
func TestExplainNotFoundLeavesAVersionedPathAlone(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app", map[string]string{"password": "one"})
	fv.deleteV2("kv2/app", 1)

	err := vault.NewSecretNotFoundError("kv2/app")
	if got := v.ExplainNotFound("kv2/app^1", err); got != err {
		t.Errorf("ExplainNotFound rewrote a versioned miss into %q", got)
	}
}

// No history means the secret itself is the best answer.
func TestExplainNotFoundOnASecretWithNoHistory(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")

	err := vault.NewSecretNotFoundError("kv2/nowhere")
	if got := v.ExplainNotFound("kv2/nowhere", err); got != err {
		t.Errorf("ExplainNotFound rewrote a plain miss into %q", got)
	}
}

// A 404 with an alive newest version was about something else entirely, and
// blaming the version would send the reader to `safe versions` for nothing.
func TestExplainNotFoundWhenTheLatestVersionIsAlive(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)
	fv.deleteV2("kv2/app", 1)

	err := vault.NewSecretNotFoundError("kv2/app")
	if got := v.ExplainNotFound("kv2/app", err); got != err {
		t.Errorf("ExplainNotFound blamed an alive version: %q", got)
	}
}
