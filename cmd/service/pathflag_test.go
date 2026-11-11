package service

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

const dashKeyID = "-Ab3cD_efGh12345"

// TestPathFlag_LeadingDashIDViaFlag pins the flag form: the id reaches the URL
// verbatim, dash and all.
func TestPathFlag_LeadingDashIDViaFlag(t *testing.T) {
	var gotPath string
	var hits atomic.Int32
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	root.SetArgs([]string{"example", "key", "revoke", "--key-id", dashKeyID})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("backend hits = %d, want 1", hits.Load())
	}
	if want := "/v1/keys/" + dashKeyID; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

// TestPathFlag_LeadingDashIDAfterSeparator pins that the pre-existing `--`
// escape still works — the flag form is an addition, not a replacement.
func TestPathFlag_LeadingDashIDAfterSeparator(t *testing.T) {
	var gotPath string
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	root.SetArgs([]string{"example", "key", "revoke", "--", dashKeyID})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if want := "/v1/keys/" + dashKeyID; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

// TestPathFlag_BareLeadingDashIDIsExplained pins the improved failure: passing
// the id bare is still a parse error (cobra cannot do otherwise), but the
// envelope's hint now tells the caller which two forms work, instead of the
// generic "run --help" that cmdutil.WrapCLIError used to attach.
func TestPathFlag_BareLeadingDashIDIsExplained(t *testing.T) {
	var hits atomic.Int32
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	})
	root.SetArgs([]string{"example", "key", "revoke", dashKeyID})
	err := root.Execute()
	if err == nil {
		t.Fatal("a bare leading-dash id must not silently succeed")
	}
	if hits.Load() != 0 {
		t.Errorf("backend hits = %d, want 0", hits.Load())
	}
	// The error must survive cmdutil.WrapCLIError as a typed validation error so
	// main emits the envelope (and exit 2) with the specific hint intact.
	ee := output.AsExitError(cmdutil.WrapCLIError(err))
	if ee == nil {
		t.Fatalf("error %v did not carry a structured envelope", err)
	}
	if ee.Type != "validation" || ee.ExitCode() != 2 {
		t.Errorf("error = %s/exit %d, want validation/exit 2", ee.Type, ee.ExitCode())
	}
	// An agent reading only the envelope must be able to retry correctly.
	for _, want := range []string{"--key-id", `"--" separator`} {
		if !strings.Contains(ee.Hint, want) {
			t.Errorf("hint should mention %q; got %q", want, ee.Hint)
		}
	}
}

// TestPathFlag_MissingValueNamesBothForms pins the omitted-argument message.
// cobra's own "accepts 1 arg(s), received 0" would not mention the flag.
// Message and hint are asserted separately: the hint always names the flag, so
// a combined check could not detect the message losing it.
func TestPathFlag_MissingValueNamesBothForms(t *testing.T) {
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be sent when the id is missing")
	})
	root.SetArgs([]string{"example", "key", "revoke"})
	err := root.Execute()
	if err == nil {
		t.Fatal("share revoke with no id must fail")
	}
	ee := output.AsExitError(cmdutil.WrapCLIError(err))
	if ee == nil {
		t.Fatalf("error %v did not carry a structured envelope", err)
	}
	for _, want := range []string{"<key-id>", "--key-id"} {
		if !strings.Contains(ee.Message, want) {
			t.Errorf("message should mention %q; got %q", want, ee.Message)
		}
	}
	if !strings.Contains(ee.Hint, `"--" separator`) {
		t.Errorf("hint should mention the -- separator; got %q", ee.Hint)
	}
}

// TestPathFlag_EmptyFlagValueIsRejected pins that a flag-supplied path value may
// not be empty. `--key-id "$SHARE_ID"` with an unset shell variable would
// otherwise address the collection URL and DELETE the wrong thing; cobra used to
// catch the equivalent as a missing positional, and MaximumNArgs no longer does.
func TestPathFlag_EmptyFlagValueIsRejected(t *testing.T) {
	var hits atomic.Int32
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	})
	root.SetArgs([]string{"example", "key", "revoke", "--key-id", ""})
	err := root.Execute()
	if err == nil {
		t.Fatal("an empty --key-id must fail rather than address the collection")
	}
	if hits.Load() != 0 {
		t.Errorf("backend hits = %d, want 0", hits.Load())
	}
	if ee := output.AsExitError(cmdutil.WrapCLIError(err)); ee == nil || ee.ExitCode() != 2 {
		t.Errorf("error = %v, want a validation error with exit 2", err)
	}
}

// TestPathFlag_FlagAndPositionalTogetherIsRejected pins that supplying both
// forms fails loudly instead of silently preferring one — an agent that does
// this has a bug, and a silent winner would hide it.
func TestPathFlag_FlagAndPositionalTogetherIsRejected(t *testing.T) {
	var hits atomic.Int32
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	})
	root.SetArgs([]string{"example", "key", "revoke", "positional-id", "--key-id", "flag-id"})
	if err := root.Execute(); err == nil {
		t.Fatal("supplying both the positional and the flag must fail")
	}
	if hits.Load() != 0 {
		t.Errorf("backend hits = %d, want 0", hits.Load())
	}
}

// TestPathFlag_HelpShowsCopyableExamples pins that the guidance is discoverable
// from --help, not only from an error the caller has to trigger first.
func TestPathFlag_HelpShowsCopyableExamples(t *testing.T) {
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {})
	leaf, _, err := root.Find([]string{"example", "key", "revoke"})
	if err != nil {
		t.Fatalf("find command: %v", err)
	}
	long := leaf.Long
	for _, want := range []string{"--key-id", "example key revoke -- -Ab3cD"} {
		if !strings.Contains(long, want) {
			t.Errorf("long help should contain %q; got:\n%s", want, long)
		}
	}
	if leaf.Flags().Lookup("key-id") == nil {
		t.Error("--key-id should be registered on the leaf")
	}
}

// TestPathFlag_UnflaggedOperationsKeepExactArgs pins the blast radius: only
// operations whose spec declares x-octo-flag on a path param relax their arity.
// Everything else keeps cobra.ExactArgs, so a missing or extra positional still
// fails the same way it always did.
func TestPathFlag_UnflaggedOperationsKeepExactArgs(t *testing.T) {
	root, _, _ := rootWithService(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be sent for a bad arg count")
	})
	// The get operation declares no path flag.
	leaf, _, err := root.Find([]string{"example", "record", "get"})
	if err != nil {
		t.Fatalf("find command: %v", err)
	}
	if leaf.Flags().Lookup("space-id") != nil {
		t.Error("space get must not gain a --space-id flag")
	}
	if err := leaf.Args(leaf, []string{}); err == nil {
		t.Error("space get with no args should still fail arity validation")
	}
	if err := leaf.Args(leaf, []string{"a", "b"}); err == nil {
		t.Error("space get with two args should still fail arity validation")
	}
}
