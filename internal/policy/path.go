package policy

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// zone says where a path lives, ordered from most to least trusted for writes.
type zone uint8

const (
	zoneWorkspace zone = iota // inside a workspace root
	zoneScratch               // /tmp, /var/tmp, /dev/null and friends
	zoneOutside               // anywhere else that is not special
	zoneSystem                // system or persistence location: reads fine, writes denied
	zoneSecret                // credentials or the gate itself: reads and writes denied
	zoneUnknown               // cannot be resolved statically
)

// env is the static context a call is judged in.
type env struct {
	home string
	art  string   // this conversation's agy artifact directory, if known
	ws   []string // cleaned, symlink-resolved workspace roots
	cwd  string   // "" when unknown (after cd to an unresolvable dir)
}

func newEnv(home string, workspace []string, cwd, conv string) *env {
	e := &env{home: home, ws: make([]string, 0, len(workspace))}
	if conv != "" && !strings.ContainsAny(conv, "/.") {
		e.art = home + "/.gemini/antigravity-cli/brain/" + conv
	}
	for _, w := range workspace {
		if w = strings.TrimSpace(w); filepath.IsAbs(w) {
			e.ws = append(e.ws, rootPath(filepath.Clean(w)))
		}
	}
	switch {
	case cwd == "" || cwd == ".":
		if len(e.ws) > 0 {
			e.cwd = e.ws[0]
		}
	default:
		e.cwd, _ = e.abs(cwd)
	}
	return e
}

// abs makes p absolute against the current directory, expanding a leading ~.
// The result is not cleaned: bash resolves "dir/link/.." physically, so ".."
// must only be applied after symlinks are resolved (see zoneOf).
// ok is false when the path depends on an unknown cwd or another user's home.
func (e *env) abs(p string) (string, bool) {
	switch {
	case p == "~":
		return e.home, true
	case strings.HasPrefix(p, "~/"):
		return e.home + p[1:], true
	case strings.HasPrefix(p, "~"):
		return "", false // ~user
	case filepath.IsAbs(p):
		return p, true
	case e.cwd == "":
		return "", false
	}
	return e.cwd + "/" + p, true
}

// zoneOf classifies a path as it would be seen by a command run in e.
func (e *env) zoneOf(p string) zone {
	a, ok := e.abs(p)
	if !ok {
		return zoneUnknown
	}
	lex := e.classify(filepath.Clean(a))
	if lex == zoneSecret {
		return zoneSecret
	}
	r := e.resolve(a)
	if r == filepath.Clean(a) {
		return lex
	}
	// A symlink can point anywhere: the resolved target decides, but a literal
	// path into a protected area stays protected even if it resolves elsewhere.
	res := e.classify(r)
	if lex == zoneSystem && res < zoneSystem {
		return zoneSystem
	}
	return res
}

func (e *env) classify(a string) zone {
	// agy keeps the agent's plans, artifacts and saved tool output here. The
	// transcript under .system_generated/logs is what the judge trusts, so the
	// agent may read it but never write it.
	if rel, ok := under(a, e.art); ok && e.art != "" {
		if rel == ".system_generated/logs" || strings.HasPrefix(rel, ".system_generated/logs/") {
			return zoneSystem
		}
		return zoneWorkspace
	}
	if e.secret(a) {
		return zoneSecret
	}
	for _, w := range e.ws {
		if rel, ok := under(a, w); ok {
			top, _, _ := strings.Cut(rel, "/")
			if wsControl[top] {
				return zoneSystem
			}
			return zoneWorkspace
		}
	}
	// Home is checked before /tmp: a home or workspace may itself live under /tmp.
	if e.persistence(a) {
		return zoneSystem
	}
	if within(a, e.home) {
		return zoneOutside
	}
	if within(a, "/tmp") || within(a, "/var/tmp") || within(a, "/dev/shm") {
		return zoneScratch
	}
	switch a {
	case "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty", "/dev/zero", "/dev/random", "/dev/urandom":
		return zoneScratch
	}
	for _, s := range systemDirs {
		if within(a, s) {
			return zoneSystem
		}
	}
	return zoneOutside
}

func (e *env) secret(a string) bool {
	if rel, ok := under(a, e.home); ok {
		for _, s := range homeSecrets {
			if rel == s || strings.HasPrefix(rel, s+"/") {
				return true
			}
		}
	}
	for _, s := range systemSecrets {
		if within(a, s) {
			return true
		}
	}
	if strings.HasPrefix(a, "/proc/") && (strings.HasSuffix(a, "/environ") || strings.HasSuffix(a, "/mem")) {
		return true
	}
	return false
}

func (e *env) persistence(a string) bool {
	rel, ok := under(a, e.home)
	if !ok {
		return false
	}
	for _, s := range homePersistence {
		if rel == s || strings.HasPrefix(rel, s+"/") {
			return true
		}
	}
	return false
}

// linkZone is the zone of the directory entry p itself: symlinks in its parent
// are resolved but a final symlink is not followed, which is what rm and mv act
// on. A trailing slash makes the kernel follow the link, so then zoneOf applies.
func (e *env) linkZone(p string) zone {
	if strings.HasSuffix(p, "/") {
		return e.zoneOf(p)
	}
	a, ok := e.abs(p)
	if !ok {
		return zoneUnknown
	}
	if lex := e.classify(filepath.Clean(a)); lex == zoneSecret || lex == zoneSystem {
		return lex
	}
	return e.classify(filepath.Join(realpath(filepath.Dir(a)), filepath.Base(a)))
}

// isRootOrAbove reports whether p is /, home, a workspace root or one of its ancestors,
// the targets a recursive delete must never have.
func (e *env) isRootOrAbove(p string) bool {
	a, ok := e.abs(p)
	if !ok {
		return true
	}
	a = realpath(a)
	switch a {
	case "/", e.home, "/tmp", "/var/tmp", "/dev/shm":
		return true
	}
	for _, w := range e.ws {
		if within(w, a) {
			return true
		}
	}
	return false
}

// secretName matches files that usually hold credentials wherever they live.
func secretName(p string) bool {
	b := filepath.Base(p)
	switch {
	case b == ".env" || strings.HasPrefix(b, ".env."),
		strings.HasPrefix(b, "id_rsa"), strings.HasPrefix(b, "id_ed25519"), strings.HasPrefix(b, "id_ecdsa"), strings.HasPrefix(b, "id_dsa"),
		strings.HasSuffix(b, ".pem"), strings.HasSuffix(b, ".key"), strings.HasSuffix(b, ".p12"), strings.HasSuffix(b, ".pfx"),
		b == ".netrc", b == ".pgpass", b == "credentials", b == ".git-credentials":
		return true
	}
	return false
}

// roots caches resolved workspace roots: they are fixed for a run and resolving
// them is most of the syscalls a decision would otherwise make.
var roots sync.Map

func rootPath(w string) string {
	if r, ok := roots.Load(w); ok {
		return r.(string)
	}
	r := realpath(w)
	roots.Store(w, r)
	return r
}

// resolve is realpath with a fast path for the common case: a ".."-free path
// below a (resolved) workspace root needs only its components below the root
// checked, and none of them is usually a symlink.
func (e *env) resolve(a string) string {
	if strings.Contains(a, "..") {
		return realpath(a)
	}
	c := filepath.Clean(a)
	for _, w := range e.ws {
		rel, ok := under(c, w)
		if !ok {
			continue
		}
		p := w
		for rel != "" {
			var part string
			part, rel, _ = strings.Cut(rel, "/")
			p += "/" + part
			fi, err := os.Lstat(p)
			if err != nil {
				return c // the rest does not exist yet, so it cannot be a link
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				return realpath(a)
			}
		}
		return c
	}
	return realpath(a)
}

// realpath resolves a path the way the kernel does: symlinks first, then "..".
// For a path that does not exist yet, its longest existing prefix is resolved
// and the rest appended, so a new file is judged by where its directory really is.
func realpath(a string) string {
	if r, err := filepath.EvalSymlinks(a); err == nil {
		return r
	}
	t := strings.TrimRight(a, "/")
	i := strings.LastIndexByte(t, '/')
	if i < 0 || t == "" {
		return filepath.Clean(a)
	}
	parent := "/"
	if i > 0 {
		parent = realpath(t[:i])
	}
	switch last := t[i+1:]; last {
	case "", ".":
		return parent
	case "..":
		return filepath.Dir(parent)
	default:
		return filepath.Join(parent, last)
	}
}

// within reports whether a equals dir or lies below it. Both must be clean.
func within(a, dir string) bool {
	_, ok := under(a, dir)
	return ok
}

func under(a, dir string) (string, bool) {
	if a == dir {
		return "", true
	}
	if dir == "/" {
		return a[1:], true
	}
	if strings.HasPrefix(a, dir) && a[len(dir)] == '/' {
		return a[len(dir)+1:], true
	}
	return "", false
}
