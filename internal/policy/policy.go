// Package policy decides agent tool calls that do not need a model: it denies
// the clearly dangerous, allows the clearly safe, and hands everything else to
// the judge together with a note on why the rules could not decide.
//
// A call is allowed only when every part of it is understood. Shell commands
// are parsed into a bash AST and every command that would run, including those
// inside pipelines, subshells, substitutions and wrappers such as bash -c, env
// or find -exec, is checked against the rules with its paths resolved.
package policy

import (
	"net/url"
	"strings"
)

// VerdictType is the outcome of the deterministic layer.
type VerdictType int

const (
	// VerdictJudge means the rules could not decide; ask the model.
	VerdictJudge VerdictType = iota
	// VerdictAllow means the call is safe to run.
	VerdictAllow
	// VerdictDeny means the call must not run.
	VerdictDeny
)

// Verdict is a decision with its reason. For VerdictJudge the reason is a
// note for the model; for VerdictDeny it is shown to the agent.
type Verdict struct {
	Type   VerdictType
	Reason string
}

// Decide judges one tool call. home is the real home directory of the user
// the agent runs as.
func Decide(call *Call, home string) Verdict {
	cwd := call.Cwd
	if cwd == "" && len(call.Workspace) > 0 {
		cwd = call.Workspace[0]
	}
	e := newEnv(home, call.Workspace, cwd, call.ConversationID)
	switch call.Tool {
	case "run_command":
		return decideShell(e, call.CommandLine)
	case "view_file", "list_dir", "find_by_name", "grep_search", "view_file_outline", "view_code_item":
		return decideRead(e, firstNonEmpty(call.AbsolutePath, call.DirectoryPath, call.SearchPath, call.SearchDirectory))
	case "write_to_file", "replace_file_content", "multi_replace_file_content":
		return decideWrite(e, call.TargetFile)
	case "read_url_content":
		return decideURL(call.Url)
	case "search_web", "ask_question", "list_permissions":
		return Verdict{Type: VerdictAllow}
	}
	return Verdict{Reason: "tool " + call.Tool + " is not covered by the rules"}
}

func decideShell(e *env, cmd string) Verdict {
	if strings.TrimSpace(cmd) == "" {
		return Verdict{Type: VerdictAllow}
	}
	r := &result{}
	w := &walker{e: e, r: r}
	w.script(cmd)
	switch {
	case r.deny != "":
		return Verdict{Type: VerdictDeny, Reason: r.deny}
	case len(r.notes) > 0:
		return Verdict{Reason: strings.Join(r.notes, "; ")}
	}
	return Verdict{Type: VerdictAllow}
}

func decideRead(e *env, p string) Verdict {
	r := &result{}
	(&walker{e: e, r: r}).read(arg{v: p})
	return toVerdict(r)
}

func decideWrite(e *env, p string) Verdict {
	if p == "" {
		return Verdict{Reason: "write without a target path"}
	}
	r := &result{}
	(&walker{e: e, r: r}).write(arg{v: p}, "writes")
	return toVerdict(r)
}

func toVerdict(r *result) Verdict {
	switch {
	case r.deny != "":
		return Verdict{Type: VerdictDeny, Reason: r.deny}
	case len(r.notes) > 0:
		return Verdict{Reason: strings.Join(r.notes, "; ")}
	}
	return Verdict{Type: VerdictAllow}
}

// docHosts serve public documentation; plain reads from them are allowed.
var docHosts = []string{
	"go.dev", "pkg.go.dev", "golang.org", "docs.python.org", "developer.mozilla.org", "docs.rs",
	"crates.io", "pypi.org", "www.npmjs.com", "nodejs.org", "readthedocs.io", "man7.org",
	"github.com", "raw.githubusercontent.com", "gitlab.com", "stackoverflow.com", "wikipedia.org",
	"kubernetes.io", "docs.docker.com", "rust-lang.org",
}

func decideURL(raw string) Verdict {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Verdict{Reason: "URL is not a plain http(s) address"}
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range blockedHosts {
		if host == h {
			return Verdict{Type: VerdictDeny, Reason: "contacts a cloud metadata endpoint"}
		}
	}
	if len(u.RawQuery) > 300 || longOpaque(u.RawQuery) || longOpaque(u.Path) {
		return Verdict{Type: VerdictDeny, Reason: "URL carries a long encoded payload, which can leak data"}
	}
	if u.RawQuery == "" && u.User == nil {
		for _, d := range docHosts {
			if host == d || strings.HasSuffix(host, "."+d) {
				return Verdict{Type: VerdictAllow}
			}
		}
	}
	return Verdict{Reason: "fetches " + host + ", which is not a known documentation site"}
}

// longOpaque reports a run of 100+ base64 or hex characters, the shape of
// data smuggled out in a URL.
func longOpaque(s string) bool {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '=' || c == '_' || c == '-' {
			if n++; n >= 100 {
				return true
			}
		} else {
			n = 0
		}
	}
	return false
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
