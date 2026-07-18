package clicore

import "math/rand"

// tipTemplates are short, one-line hints surfaced occasionally in interactive
// CLI sessions to teach a feature. Keep each to a single line, imperative, and
// genuinely useful. "%s" is the command name. Shown only on a TTY, never in
// scripts/pipes/--json, and suppressible via SHARE2US_NO_TIPS=1.
var tipTemplates = []string{
	"Tip: `%s <file> --expires 24h` sets how long a link stays live.",
	"Tip: `%s <file> --to alex@acme.dev` locks a share to one recipient.",
	"Tip: `%s <text> --password` puts a share behind a password.",
	"Tip: `%s ls` lists your active shares; add `--json` for scripting.",
	"Tip: `%s revoke <id>` kills a share instantly — the file is tombstoned.",
	"Tip: `%s <file> --device laptop` sends an end-to-end encrypted copy to your own device.",
	"Tip: `%s <file> --email teammate@work.com` shares end-to-end with a contact's device.",
	"Tip: `%s receive` pulls files sent to this device's inbox.",
	"Tip: `%s tui` opens the terminal UI to browse and manage shares.",
	"Tip: `%s usage` shows your storage and share quota at a glance.",
	"Tip: Set SHARE2US_API_TOKEN to a scoped token to use %s in CI.",
	"Tip: `%s devices` lists your logged-in devices; revoke any you don't recognize.",
	"Tip: A share link never leaks its filename — it's an opaque, unguessable id.",
	"Tip: `%s extend <id> 7d` pushes back a share's expiry.",
	"Tip: Turn these tips off with SHARE2US_NO_TIPS=1.",
}

// Tips returns the tip lines rendered for the given command name.
func Tips(command string) []string {
	if command == "" {
		command = "s2u"
	}
	out := make([]string, len(tipTemplates))
	for i, t := range tipTemplates {
		out[i] = renderTip(t, command)
	}
	return out
}

// RandomTip returns a single random tip for the command (or "" if none).
func RandomTip(command string) string {
	if len(tipTemplates) == 0 {
		return ""
	}
	return renderTip(tipTemplates[rand.Intn(len(tipTemplates))], command)
}

// renderTip fills every "%s" placeholder with the command name (some templates
// use it more than once).
func renderTip(tmpl, command string) string {
	out := make([]byte, 0, len(tmpl)+len(command))
	for i := 0; i < len(tmpl); i++ {
		if i+1 < len(tmpl) && tmpl[i] == '%' && tmpl[i+1] == 's' {
			out = append(out, command...)
			i++
			continue
		}
		out = append(out, tmpl[i])
	}
	return string(out)
}
