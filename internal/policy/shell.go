package policy

import (
	"strings"
	"sync"

	"mvdan.cc/sh/v3/syntax"
)

// maxDepth bounds nested shells and wrappers (bash -c "env nohup sh -c ...").
// Deeper nesting has no legitimate use and is treated as obfuscation.
const maxDepth = 8

var parsers = sync.Pool{New: func() any { return syntax.NewParser(syntax.Variant(syntax.LangBash)) }}

func parse(src string) (*syntax.File, error) {
	p := parsers.Get().(*syntax.Parser)
	defer parsers.Put(p)
	return p.Parse(strings.NewReader(src), "")
}

// kind says how much of a word's value is known before the shell runs it.
type kind uint8

const (
	static  kind = iota // fully known
	glob                // known text containing unquoted glob characters
	dynamic             // depends on expansions or command output
)

type arg struct {
	v    string // value after quote removal
	kind kind
}

// result collects the outcome of every command in a script. The first deny wins;
// judge notes explain to the model why the rules could not decide.
type result struct {
	deny  string
	notes []string
}

func (r *result) denyf(reason string) {
	if r.deny == "" {
		r.deny = reason
	}
}

func (r *result) judgef(note string) {
	if len(r.notes) < 4 {
		r.notes = append(r.notes, note)
	}
}

// walker visits a parsed script the way bash would execute it, tracking the
// working directory and where stdin comes from.
type walker struct {
	e     *env
	r     *result
	depth int
	stdin stdinSource
	here  string // static heredoc body when stdin == fromHeredoc
}

type stdinSource uint8

const (
	fromTerminal stdinSource = iota
	fromPipe
	fromHeredoc
)

// fork returns a walker for a subshell: same result, private copy of the env.
func (w *walker) fork() *walker {
	e := *w.e
	c := *w
	c.e = &e
	c.stdin, c.here = fromTerminal, ""
	return &c
}

func (w *walker) script(src string) {
	if w.depth > maxDepth {
		w.r.denyf("nests shells or wrappers too deeply to inspect")
		return
	}
	f, err := parse(src)
	if err != nil {
		w.r.judgef("the command could not be parsed as bash")
		return
	}
	w.stmts(f.Stmts)
}

func (w *walker) stmts(ss []*syntax.Stmt) {
	for _, s := range ss {
		w.stmt(s)
	}
}

func (w *walker) stmt(s *syntax.Stmt) {
	if s.Coprocess {
		w.r.judgef("starts a coprocess")
	}
	c := *w
	c.stdin, c.here = w.stdin, w.here
	for _, rd := range s.Redirs {
		c.redirect(rd)
	}
	if s.Cmd != nil {
		c.cmd(s.Cmd)
	}
}

func (w *walker) redirect(rd *syntax.Redirect) {
	switch rd.Op {
	case syntax.Hdoc, syntax.DashHdoc:
		w.nested(rd.Hdoc)
		if a := w.word(rd.Hdoc); a.kind == static {
			w.stdin, w.here = fromHeredoc, a.v
		} else {
			w.stdin, w.here = fromHeredoc, ""
		}
		return
	case syntax.WordHdoc:
		a := w.word(rd.Word)
		w.stdin, w.here = fromHeredoc, ""
		if a.kind == static {
			w.here = a.v
		}
		return
	case syntax.DplIn, syntax.DplOut:
		if a := w.word(rd.Word); a.kind == static && (a.v == "-" || isDigits(a.v)) {
			return // fd duplication, not a file
		}
		w.write(w.word(rd.Word), "redirects output to")
	case syntax.RdrIn:
		w.read(w.word(rd.Word))
		w.stdin = fromTerminal
	case syntax.RdrInOut:
		w.write(w.word(rd.Word), "opens for writing")
	default: // >, >>, >|, &>, &>>
		w.write(w.word(rd.Word), "redirects output to")
	}
}

func (w *walker) cmd(c syntax.Command) {
	switch c := c.(type) {
	case *syntax.CallExpr:
		w.call(c)
	case *syntax.BinaryCmd:
		switch c.Op {
		case syntax.Pipe, syntax.PipeAll:
			// Each side of a pipe runs in its own subshell.
			w.fork().stmt(c.X)
			y := w.fork()
			y.stdin = fromPipe
			y.stmt(c.Y)
		default: // && and ||
			w.stmt(c.X)
			w.stmt(c.Y)
		}
	case *syntax.Subshell:
		w.fork().stmts(c.Stmts)
	case *syntax.Block:
		w.stmts(c.Stmts)
	case *syntax.IfClause:
		w.branch(func() {
			for ic := c; ic != nil; ic = ic.Else {
				w.stmts(ic.Cond)
				w.stmts(ic.Then)
			}
		})
	case *syntax.WhileClause:
		w.branch(func() { w.stmts(c.Cond); w.stmts(c.Do) })
	case *syntax.ForClause:
		if wi, ok := c.Loop.(*syntax.WordIter); ok {
			for _, it := range wi.Items {
				w.nested(it)
			}
		} else {
			w.nested(c.Loop)
		}
		w.branch(func() { w.stmts(c.Do) })
	case *syntax.CaseClause:
		w.nested(c.Word)
		w.branch(func() {
			for _, ci := range c.Items {
				w.stmts(ci.Stmts)
			}
		})
	case *syntax.FuncDecl:
		// The body is checked here; calls to the function by name are then
		// judged as unknown commands, which is conservative.
		w.fork().stmt(c.Body)
	case *syntax.DeclClause:
		for _, as := range c.Args {
			w.assign(as)
		}
	case *syntax.TimeClause:
		if c.Stmt != nil {
			w.stmt(c.Stmt)
		}
	case *syntax.ArithmCmd, *syntax.LetClause, *syntax.TestClause:
		w.nested(c)
	default:
		w.r.judgef("uses shell syntax the gate does not inspect")
	}
}

// branch runs f and forgets the working directory if f may have changed it,
// since which branch runs is unknown statically.
func (w *walker) branch(f func()) {
	cwd := w.e.cwd
	f()
	if w.e.cwd != cwd {
		w.e.cwd = ""
	}
}

func (w *walker) call(c *syntax.CallExpr) {
	for _, as := range c.Assigns {
		w.assign(as)
		if len(c.Args) > 0 && as.Name != nil && !safeEnv[as.Name.Value] {
			w.r.judgef("sets " + as.Name.Value + " for the command")
		}
	}
	if len(c.Args) == 0 {
		return
	}
	args := make([]arg, len(c.Args))
	for i, wd := range c.Args {
		w.nested(wd)
		args[i] = w.word(wd)
	}
	w.exec(args, 0)
}

func (w *walker) assign(as *syntax.Assign) {
	if as.Name != nil && hijackVars[as.Name.Value] {
		w.r.denyf("sets " + as.Name.Value + ", which changes what programs run")
	}
	if as.Value != nil {
		w.nested(as.Value)
	}
	if as.Array != nil {
		w.nested(as.Array)
	}
}

// nested walks every command substitution, process substitution and nested
// script inside node as its own subshell.
func (w *walker) nested(node syntax.Node) {
	if node == nil {
		return
	}
	syntax.Walk(node, func(n syntax.Node) bool {
		switch n := n.(type) {
		case *syntax.CmdSubst:
			w.fork().stmts(n.Stmts)
			return false
		case *syntax.ProcSubst:
			w.fork().stmts(n.Stmts)
			return false
		}
		return true
	})
}

// word returns a word's value after quote removal as bash would see it,
// resolving only $HOME and $PWD.
func (w *walker) word(wd *syntax.Word) arg {
	if wd == nil {
		return arg{kind: dynamic}
	}
	var b strings.Builder
	k := static
	isGlob := false
	var parts func(ps []syntax.WordPart, quoted bool)
	parts = func(ps []syntax.WordPart, quoted bool) {
		for _, p := range ps {
			switch p := p.(type) {
			case *syntax.Lit:
				v := p.Value
				if !quoted {
					if braceExpands(v) {
						k = dynamic
					}
					for i := 0; i < len(v); i++ {
						switch c := v[i]; c {
						case '\\':
							if i+1 < len(v) {
								i++
								b.WriteByte(v[i])
							}
						case '*', '?', '[':
							isGlob = true
							b.WriteByte(c)
						default:
							b.WriteByte(c)
						}
					}
				} else {
					b.WriteString(unescapeDQ(v))
				}
			case *syntax.SglQuoted:
				if p.Dollar {
					k = dynamic // $'..' escapes are an obfuscation channel
				}
				b.WriteString(p.Value)
			case *syntax.DblQuoted:
				parts(p.Parts, true)
			case *syntax.ParamExp:
				if v, ok := w.param(p); ok {
					b.WriteString(v)
				} else {
					k = dynamic
				}
			default:
				k = dynamic
			}
		}
	}
	parts(wd.Parts, false)
	v := b.String()
	switch {
	case k == dynamic:
		return arg{v: v, kind: dynamic}
	case isGlob:
		return arg{v: v, kind: glob}
	}
	return arg{v: v}
}

func (w *walker) param(p *syntax.ParamExp) (string, bool) {
	if p.Excl || p.Length || p.Width || p.Index != nil || p.Slice != nil || p.Repl != nil || p.Names != 0 || p.Exp != nil || p.Param == nil {
		return "", false
	}
	switch p.Param.Value {
	case "HOME":
		return w.e.home, true
	case "PWD":
		return w.e.cwd, w.e.cwd != ""
	}
	return "", false
}

func unescapeDQ(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0 {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// braceExpands reports whether bash would brace-expand v ({a,b} or {1..3});
// a bare {} as used by find -exec is left alone.
func braceExpands(v string) bool {
	i := strings.IndexByte(v, '{')
	if i < 0 {
		return false
	}
	j := strings.IndexByte(v[i:], '}')
	if j < 0 {
		return false
	}
	in := v[i+1 : i+j]
	return strings.Contains(in, ",") || strings.Contains(in, "..")
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// read checks a path the command reads.
func (w *walker) read(a arg) {
	if a.kind == dynamic {
		w.r.judgef("reads a path built from expansions")
		return
	}
	p := globBase(a)
	if strings.HasPrefix(p, "/dev/tcp/") || strings.HasPrefix(p, "/dev/udp/") {
		w.r.denyf("opens a raw network connection through " + p)
		return
	}
	z := w.e.zoneOf(p)
	switch {
	case z == zoneSecret:
		w.r.denyf("reads a protected credential or gate path: " + p)
	case secretName(p) && z != zoneWorkspace:
		w.r.denyf("reads a credential file outside the workspace: " + p)
	case secretName(p):
		w.r.judgef("reads a file that may hold credentials: " + p)
	case z == zoneUnknown:
		w.r.judgef("reads a path whose location is unknown: " + p)
	}
}

// write checks a path the command creates, changes or deletes.
func (w *walker) write(a arg, what string) {
	if a.kind == dynamic {
		w.r.judgef(what + " a path built from expansions")
		return
	}
	p := globBase(a)
	if strings.HasPrefix(p, "/dev/tcp/") || strings.HasPrefix(p, "/dev/udp/") {
		w.r.denyf("opens a raw network connection through " + p)
		return
	}
	switch w.e.zoneOf(p) {
	case zoneWorkspace, zoneScratch:
		if a.kind == glob {
			return
		}
	case zoneSecret:
		w.r.denyf(what + " a protected credential or gate path: " + p)
	case zoneSystem:
		w.r.denyf(what + " a system, startup or .git internal path: " + p)
	case zoneOutside:
		w.r.judgef(what + " a path outside the workspace: " + p)
	default:
		w.r.judgef(what + " a path whose location is unknown: " + p)
	}
}

// globBase is the directory a glob can match in: the text before the first
// metacharacter up to its last slash, or the current directory.
func globBase(a arg) string {
	if a.kind != glob {
		return a.v
	}
	v := a.v
	if m := strings.IndexAny(v, "*?["); m >= 0 {
		v = v[:m]
	}
	i := strings.LastIndexByte(v, '/')
	switch {
	case i < 0:
		return "."
	case i == 0:
		return "/"
	}
	return v[:i]
}
