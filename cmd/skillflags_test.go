package cmd

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/registry"
	"github.com/Mininglamp-OSS/octo-cli/skills"
)

// Check the flags used by the bundled guidance against the command tree.
func TestSkills_EveryDocumentedFlagExists(t *testing.T) {
	tf := cmdutil.NewTestFactory()
	tf.RegistryFunc = registry.MustNew
	root := NewRootCmd(tf.Factory)

	entries, err := fs.Glob(skills.FS, "*/*.md")
	if err != nil {
		t.Fatalf("glob skills: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no skill documents were found, so this test asserted nothing")
	}

	var checkedCommands, checkedFlags, unresolved int
	for _, name := range entries {
		raw, rerr := fs.ReadFile(skills.FS, name)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		for _, inv := range documentedInvocations(string(raw)) {
			cmd, remaining := resolveDocumentedCommand(root, inv.words)
			if cmd == nil {
				// A skill may name a command from another tool; arity and placeholders
				// are checked elsewhere. Counted so a silent collapse in resolution is
				// visible in the log rather than mistaken for a clean run.
				unresolved++
				continue
			}
			checkedCommands++
			for _, flag := range documentedFlags(remaining) {
				checkedFlags++
				if !commandAcceptsFlag(cmd, flag) {
					t.Errorf("%s:%d uses %s, which %q does not define:\n    %s",
						name, inv.line, flag, cmd.CommandPath(), inv.text)
				}
			}
		}
	}
	if checkedCommands == 0 || checkedFlags == 0 {
		t.Fatalf("resolved %d commands and %d flags — the extractor matched nothing, so this "+
			"test would stay green whatever the skills said", checkedCommands, checkedFlags)
	}
	t.Logf("checked %d flag uses across %d resolvable octo-cli invocations in %d skill documents "+
		"(%d lines did not resolve to a command)", checkedFlags, checkedCommands, len(entries), unresolved)
}

// documentedInvocation is one `octo-cli …` command line lifted out of a skill document.
type documentedInvocation struct {
	line  int
	text  string
	words []string
}

// octoCLIInvocation finds an `octo-cli` call anywhere on a line, including inside a `$( … )`
// capture.
var octoCLIInvocation = regexp.MustCompile(`octo-cli\s+([^)|;&\n]+)`)

// trailingComment matches a shell comment, whose contents are prose rather than argv. Several
// skills annotate a command with `# -> {…}`, and the arrow would otherwise be read as a flag.
var trailingComment = regexp.MustCompile(`\s#.*$`)

// documentedInvocations extracts every octo-cli command line from a skill document.
//
// Continuation lines are joined first: a recipe that wraps a long call across a trailing
// backslash would otherwise have its later flags invisible to this test, which is exactly the
// kind of gap that lets a bad flag survive.
func documentedInvocations(doc string) []documentedInvocation {
	var out []documentedInvocation
	lines := strings.Split(doc, "\n")
	for i := 0; i < len(lines); i++ {
		joined, start := lines[i], i
		for strings.HasSuffix(strings.TrimRight(joined, " \t"), `\`) && i+1 < len(lines) {
			joined = strings.TrimRight(strings.TrimRight(joined, " \t"), `\`) + " " + strings.TrimSpace(lines[i+1])
			i++
		}
		joined = trailingComment.ReplaceAllString(joined, "")
		for _, m := range octoCLIInvocation.FindAllStringSubmatch(joined, -1) {
			// The inner command in a nested substitution is checked separately.
			argv := m[1]
			if i := strings.Index(argv, "$("); i >= 0 {
				argv = argv[:i]
			}
			// Prose delimits an inline command with backticks, so a sentence like "run
			// `octo-cli auth --help`, or …" would otherwise yield the token
			// "--help`," and be reported as an undefined flag.
			if i := strings.IndexByte(argv, '`'); i >= 0 {
				argv = argv[:i]
			}
			words := strings.Fields(argv)
			if len(words) == 0 {
				continue
			}
			out = append(out, documentedInvocation{line: start + 1, text: strings.TrimSpace(joined), words: words})
		}
	}
	return out
}

// resolveDocumentedCommand walks the leading words down the command tree and returns the
// deepest command that matched, plus the words left over (arguments and flags).
//
// Returns nil when the first word is not a known command, so a line naming another tool is
// skipped rather than reported as a failure.
func resolveDocumentedCommand(root *cobra.Command, words []string) (resolved *cobra.Command, remaining []string) {
	cur := root
	i := 0
	for ; i < len(words); i++ {
		word := words[i]
		if strings.HasPrefix(word, "-") {
			break
		}
		child := findDocumentedChild(cur, word)
		if child == nil {
			break
		}
		cur = child
	}
	if cur == root {
		return nil, nil
	}
	return cur, words[i:]
}

func findDocumentedChild(parent *cobra.Command, name string) *cobra.Command {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
		for _, alias := range c.Aliases {
			if alias == name {
				return c
			}
		}
	}
	return nil
}

// documentedFlags returns the flag tokens in a command's argument list, normalised to the
// spelling a user typed: `--name=value` and `-q '…'` both reduce to the flag itself.
//
// Everything after a bare `--` is an operand by definition and is skipped, since that is the
// documented escape for an id beginning with "-".
func documentedFlags(words []string) []string {
	var out []string
	for _, w := range words {
		if w == "--" {
			break
		}
		if !strings.HasPrefix(w, "-") || w == "-" {
			continue
		}
		if name, _, found := strings.Cut(w, "="); found {
			out = append(out, name)
			continue
		}
		out = append(out, w)
	}
	return out
}

// commandAcceptsFlag reports whether cmd would accept the flag as spelled, checking its own
// flags, the persistent flags it inherits, and — for a short cluster like `-rq` — every letter
// in it.
//
// InitDefaultHelpFlag first, because cobra adds -h/--help during Execute rather than at
// construction: without it a documented `--help` would be reported as undefined.
func commandAcceptsFlag(cmd *cobra.Command, flag string) bool {
	cmd.InitDefaultHelpFlag()
	if long, ok := strings.CutPrefix(flag, "--"); ok {
		return lookupDocumentedFlag(cmd, long) != nil
	}
	for _, r := range strings.TrimPrefix(flag, "-") {
		if lookupDocumentedShorthand(cmd, string(r)) == nil {
			return false
		}
	}
	return true
}

func lookupDocumentedFlag(cmd *cobra.Command, name string) any {
	if f := cmd.Flags().Lookup(name); f != nil {
		return f
	}
	if f := cmd.InheritedFlags().Lookup(name); f != nil {
		return f
	}
	return nil
}

func lookupDocumentedShorthand(cmd *cobra.Command, letter string) any {
	if f := cmd.Flags().ShorthandLookup(letter); f != nil {
		return f
	}
	if f := cmd.InheritedFlags().ShorthandLookup(letter); f != nil {
		return f
	}
	return nil
}

// TestSkills_ExtractorSeesTheFlagsItClaimsTo guards the tripwire against itself. A regex-based
// extractor that silently stops matching would leave the test above green forever, which is
// the failure mode it exists to prevent — so the shapes the skills actually use are pinned
// against a fixture with known content.
func TestSkills_ExtractorSeesTheFlagsItClaimsTo(t *testing.T) {
	doc := strings.Join([]string{
		"VERSION=$(octo-cli version -q '.data.version')",
		"octo-cli api GET /v1/items --params '{}' --dry-run",
		"RESULT=$(octo-cli api POST /v1/items --timeout 30s \\",
		"  --data '{}' -q '.data.id')",
		"octo-cli api GET -- --starts-with-dash",
		"some-other-tool --not-ours",
	}, "\n")

	invs := documentedInvocations(doc)
	if len(invs) != 4 {
		t.Fatalf("extracted %d invocations, want 4: %+v", len(invs), invs)
	}

	tf := cmdutil.NewTestFactory()
	tf.RegistryFunc = registry.MustNew
	root := NewRootCmd(tf.Factory)
	var got []string
	for _, inv := range invs {
		cmd, remaining := resolveDocumentedCommand(root, inv.words)
		if cmd == nil {
			t.Fatalf("could not resolve %q", inv.text)
		}
		got = append(got, documentedFlags(remaining)...)
	}
	want := []string{"-q", "--params", "--dry-run", "--timeout", "--data", "-q"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("flags = %v, want %v — the continuation-line join or the `--` cut regressed", got, want)
	}

	// A flag that does not exist must be reported, or the tripwire is decorative.
	cmd, _ := resolveDocumentedCommand(root, strings.Fields("api POST /v1/items"))
	if cmd == nil {
		t.Fatal("api did not resolve")
	}
	if commandAcceptsFlag(cmd, "--definitely-not-a-flag") {
		t.Error("commandAcceptsFlag accepted a flag that does not exist")
	}
	if !commandAcceptsFlag(cmd, "-q") {
		t.Error("commandAcceptsFlag rejected the global --jq shorthand, which every recipe uses")
	}
}
