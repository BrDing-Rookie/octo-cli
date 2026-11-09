//go:build darwin || linux

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

const (
	authCurrentOutputProcessArg = "--test-auth-current-output"
	authCurrentRawStdout        = "--raw-stdout"
)

func TestUnifiedAuthCurrentCancelWhileWritingOutput(t *testing.T) {
	for _, tc := range []struct {
		name, code, diagnostic string
		args                   []string
		wantCalls              int
		commits                bool
	}{
		{"online get", "NETWORK_ERROR", "", []string{"auth", "get"}, 1, false},
		{"dry-run get", "NETWORK_ERROR", "", []string{"--dry-run", "auth", "get"}, 0, false},
		{"login", "TOKEN_IMPORT_OUTPUT_FAILED", "", []string{"--profile", "target", "auth", "login", "--with-token"}, 1, true},
		{"filtered login", "TOKEN_IMPORT_OUTPUT_FAILED", "", []string{"--profile", "target", "--jq", ".data.profile", "auth", "login", "--with-token"}, 1, true},
		{"verbose trace", "NETWORK_ERROR", "[octo] GET ", []string{"--verbose", "auth", "get"}, 0, false},
		{"invalid timeout", "NETWORK_ERROR", "warning: invalid --timeout", []string{"--timeout", "invalid-duration", "auth", "get"}, 0, false},
		{"cleanup warning", "TOKEN_IMPORT_OUTPUT_FAILED", "previous managed credential could not be removed", []string{"--profile", "target", "--jq", ".data.profile", "auth", "login", "--with-token"}, 1, true},
	} {
		for _, run := range []struct {
			sig    syscall.Signal
			merged bool
		}{
			{syscall.SIGINT, false}, {syscall.SIGTERM, false},
			{syscall.SIGINT, true}, {syscall.SIGTERM, true},
		} {
			if tc.diagnostic != "" && !tc.commits && !run.merged {
				continue // These request diagnostics precede the HTTP call.
			}
			name := tc.name + "/" + run.sig.String()
			if run.merged {
				name += "/merged"
			}
			t.Run(name, func(t *testing.T) {
				dir := phaseOneEnv(t)
				old, candidate := authCurrentFixtureStoredToken, authCurrentFixtureCandidateToken
				server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{
					old:       authCurrentFixtureSuccess("old-id", "owner", "space"),
					candidate: authCurrentFixtureSuccess("candidate-id", "owner", "space"),
				})
				t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
				t.Setenv(config.EnvToken, old)
				t.Setenv(config.EnvAPIBaseURL, server.URL)
				store := authstore.NewManagedStore(dir, nil)
				var originalEntry string
				if tc.commits {
					originalEntry = seedAuthCurrentProfile(t, store, "target", server.URL, "space", old)
					if tc.diagnostic != "" {
						obstructAuthCurrentCleanup(t, dir, originalEntry)
					}
				}

				var watchDiagnostic string
				if run.merged {
					watchDiagnostic = tc.diagnostic
				}
				stderr := cancelAuthCurrentOutputProcess(t, run.sig, run.merged, watchDiagnostic, candidate, tc.args)
				if !run.merged {
					if tc.diagnostic != "" {
						warning, envelope, _ := bytes.Cut(stderr, []byte("\n"))
						if !strings.Contains(string(warning), tc.diagnostic) {
							t.Fatalf("missing cleanup warning on writable stderr: %s", stderr)
						}
						stderr = envelope
					}
					var envelope struct {
						Error struct{ Code string }
					}
					if err := json.Unmarshal(stderr, &envelope); err != nil || envelope.Error.Code != tc.code {
						t.Fatalf("expected %s after cancellation: %s (%v)", tc.code, stderr, err)
					}
					assertAuthCurrentRedaction(t, candidate, string(stderr))
				}
				if got := len(requests()); got != tc.wantCalls {
					t.Fatalf("got %d gateway requests, want %d", got, tc.wantCalls)
				}
				if !tc.commits {
					if _, err := os.Stat(filepath.Join(dir, "config.json")); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("auth get wrote a Profile: %v", err)
					}
					return
				}
				assertAuthCurrentCommittedToken(t, store, originalEntry, candidate)
			})
		}
	}
}

func TestUnifiedAuthCurrentBrokenStdoutPreservesCommittedToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"plain", nil},
		{"filtered", []string{"--jq", ".data.profile"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := phaseOneEnv(t)
			t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
			store := authstore.NewManagedStore(dir, nil)
			candidate := authCurrentFixtureCandidateToken
			server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{
				candidate: authCurrentFixtureSuccess("candidate-id", "owner", "space"),
			})
			originalEntry := seedAuthCurrentProfile(t, store, "target", server.URL, "space", authCurrentFixtureStoredToken)
			reader, stdout := authCurrentTestPipe(t)
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			args := []string{authCurrentOutputProcessArg, authCurrentRawStdout, "--format", "json", "--profile", "target"}
			args = append(args, tc.args...)
			args = append(args, "auth", "login", "--with-token")
			proc := exec.CommandContext(ctx, os.Args[0], args...)
			proc.Stdin = strings.NewReader(candidate)
			proc.Stdout = stdout
			var stderr bytes.Buffer
			proc.Stderr = &stderr
			var exit *exec.ExitError
			if err := proc.Run(); !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("expected login to exit with code 1 after broken stdout: %v (%s)", err, stderr.String())
			}
			var envelope struct {
				Error struct{ Code string }
			}
			if err := json.Unmarshal(stderr.Bytes(), &envelope); err != nil || envelope.Error.Code != "TOKEN_IMPORT_OUTPUT_FAILED" {
				t.Fatalf("expected the post-commit error envelope: %s (%v)", stderr.String(), err)
			}
			assertAuthCurrentRedaction(t, candidate, stderr.String())
			if len(requests()) != 1 {
				t.Fatal("expected one candidate verification request")
			}
			assertAuthCurrentCommittedToken(t, store, originalEntry, candidate)
		})
	}
}

func TestUnifiedAuthCurrentBrokenStderrPreservesSuccessfulImport(t *testing.T) {
	dir := phaseOneEnv(t)
	t.Setenv(config.EnvCredentialMode, config.CredentialModeUnified)
	store := authstore.NewManagedStore(dir, nil)
	candidate := authCurrentFixtureCandidateToken
	server, requests := newAuthCurrentFixture(t, map[string]authCurrentFixtureReply{
		candidate: authCurrentFixtureSuccess("candidate-id", "owner", "space"),
	})
	originalEntry := seedAuthCurrentProfile(t, store, "target", server.URL, "space", authCurrentFixtureStoredToken)
	obstructAuthCurrentCleanup(t, dir, originalEntry)
	reader, stderr := authCurrentTestPipe(t)
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	proc := exec.CommandContext(ctx, os.Args[0], authCurrentOutputProcessArg, authCurrentRawStdout,
		"--format", "json", "--profile", "target", "--jq", ".data.profile", "auth", "login", "--with-token")
	proc.Stdin = strings.NewReader(candidate)
	proc.Stderr = stderr
	stdout, err := proc.Output()
	if err != nil || string(stdout) != "\"target\"\n" {
		t.Fatalf("expected exit code 0 and complete jq output after broken stderr: %v (%q)", err, stdout)
	}
	if len(requests()) != 1 {
		t.Fatal("expected one candidate verification request")
	}
	assertAuthCurrentCommittedToken(t, store, originalEntry, candidate)
}

func assertAuthCurrentCommittedToken(t *testing.T, store *authstore.ManagedStore, originalEntry, candidate string) {
	t.Helper()
	snap, err := store.Snapshot("target", true)
	if err != nil || snap.Profile.TokenSource == nil || snap.Profile.TokenSource.Entry == originalEntry {
		t.Fatalf("expected the committed Profile after output failure: %+v (%v)", snap, err)
	}
	cfg, err := config.LoadProfileConfig()
	if err != nil {
		t.Fatal(err)
	}
	token, err := authstore.ReadManagedToken(cfg, snap.Profile.TokenSource)
	if err != nil || token != candidate {
		t.Fatalf("expected the committed Token after output failure: %v", err)
	}
}

func obstructAuthCurrentCleanup(t *testing.T, dir, entry string) {
	t.Helper()
	path := filepath.Join(dir, "credentials", entry+".enc")
	// Only the old entry's removal fails. New encrypted entries can still be staged.
	if err := os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".retained", filepath.Join(path, "retained")); err != nil {
		t.Fatal(err)
	}
}

func cancelAuthCurrentOutputProcess(t *testing.T, sig syscall.Signal, merged bool, watchDiagnostic, stdin string, args []string) []byte {
	t.Helper()
	_, stdout := authCurrentTestPipe(t)
	fillAuthCurrentStdoutPipe(t, stdout)
	ready, notify := authCurrentTestPipe(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	childArgs := append([]string{authCurrentOutputProcessArg, watchDiagnostic, "--format", "json"}, args...)
	proc := exec.CommandContext(ctx, os.Args[0], childArgs...)
	proc.Stdout = stdout
	proc.Stdin = strings.NewReader(stdin)
	proc.ExtraFiles = []*os.File{notify}
	var stderr bytes.Buffer
	proc.Stderr = &stderr
	if merged {
		proc.Stderr = stdout
	}
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if proc.ProcessState == nil {
			_ = proc.Process.Kill()
			_ = proc.Wait()
		}
	}()
	_ = notify.Close()
	if err := ready.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var marker [1]byte
	if _, err := io.ReadFull(ready, marker[:]); err != nil {
		_ = proc.Process.Kill()
		_ = proc.Wait()
		t.Fatalf("child did not reach the expected write: %v (%s)", err, stderr.String())
	}
	signalledAt := time.Now()
	if err := proc.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err := proc.Wait(); !errors.As(err, &exit) || exit.ExitCode() != 1 || time.Since(signalledAt) > 3*time.Second {
		t.Fatalf("expected the CLI to exit promptly with code 1 after %s: %v (%s)", sig, err, stderr.String())
	}
	return stderr.Bytes()
}

func authCurrentTestPipe(t *testing.T) (reader, writer *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	return reader, writer
}

func fillAuthCurrentStdoutPipe(t *testing.T, pipe *os.File) {
	t.Helper()
	fd := int(pipe.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	padding := make([]byte, 4096)
	for {
		_, err := unix.Write(fd, padding)
		if errors.Is(err, unix.EAGAIN) {
			if len(padding) == 1 {
				break
			}
			// Fill the remainder so even a short jq result blocks.
			padding = padding[:1]
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
}

type authCurrentNotifyingWriter struct {
	out, ready *os.File
	match      string
}

func (w authCurrentNotifyingWriter) Write(data []byte) (int, error) {
	if w.match == "" || bytes.Contains(data, []byte(w.match)) {
		if _, err := w.ready.Write([]byte{1}); err != nil {
			return 0, err
		}
	}
	return w.out.Write(data)
}

// The test subprocess uses the fixture environment before TestMain sweeps it.
func init() {
	if len(os.Args) < 3 || os.Args[1] != authCurrentOutputProcessArg {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	f := cmdutil.NewDefaultFactory()
	store := authstore.NewManagedStore(os.Getenv("OCTO_CONFIG_DIR"), nil)
	f.ManagedStoreFunc = func() (*authstore.ManagedStore, error) { return store, nil }
	if watchDiagnostic := os.Args[2]; watchDiagnostic != authCurrentRawStdout {
		ready := os.NewFile(3, "ready")
		if watchDiagnostic != "" {
			f.IOStreams.ErrOut = authCurrentNotifyingWriter{out: os.Stderr, ready: ready, match: watchDiagnostic}
		} else {
			f.IOStreams.Out = authCurrentNotifyingWriter{out: os.Stdout, ready: ready}
		}
	}
	root := NewRootCmd(f)
	root.SetArgs(os.Args[3:])
	err := root.ExecuteContext(ctx)
	stop()
	if err != nil {
		if exit := output.AsExitError(err); exit != nil {
			os.Exit(exit.ExitCode())
		}
		os.Exit(2)
	}
	os.Exit(0)
}
