// Package skills embeds the agent-facing SKILL.md documents so the binary can
// export them via `octo-cli skills` without shipping separate files alongside it.
package skills

import "embed"

// FS holds every markdown doc under each <skill-name>/ directory: the skill's
// own SKILL.md plus its reference files, keyed by relative path. Listing uses
// */SKILL.md; the sibling .md files are reference docs loaded on demand.
//
//go:embed */*.md
var FS embed.FS
