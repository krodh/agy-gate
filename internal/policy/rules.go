package policy

import (
	"path/filepath"
	"strings"
)

// Paths below $HOME that hold credentials or could be used to disable the gate.
// Reads and writes are both denied.
var homeSecrets = []string{
	".ssh", ".gnupg", ".aws", ".azure", ".config/gcloud", ".kube", ".docker",
	".netrc", ".git-credentials", ".config/gh", ".config/hub", ".password-store",
	".pgpass", ".npmrc", ".pypirc", ".cargo/credentials", ".cargo/credentials.toml",
	".mozilla", ".config/google-chrome", ".config/chromium", ".local/share/keyrings",
	".gemini", ".claude", ".codex", ".config/agy-profiles", ".config/agy-gate",
	".local/state/agy-gate", ".local/bin",
}

var systemSecrets = []string{
	"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d", "/etc/rancher",
	"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key",
	"/root", "/run/user", "/var/run/docker.sock", "/run/docker.sock",
}

// Startup and configuration files under $HOME: fine to read, never to write.
var homePersistence = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc",
	".zprofile", ".zshenv", ".config/fish", ".config/systemd", ".config/autostart",
	".config/environment.d", ".xinitrc", ".xprofile", ".gitconfig", ".config/git",
	".config/go/env", ".pam_environment", ".inputrc",
}

var systemDirs = []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/opt", "/var", "/srv", "/sys", "/proc", "/dev", "/snap"}

// Directories inside a workspace whose contents make tools run code later:
// .git/config and .git/hooks for git, and agy's own customization folders,
// which can hold hooks, MCP servers and agents that run outside the gate.
var wsControl = map[string]bool{".git": true, ".agents": true, ".agent": true, "_agents": true, "_agent": true, ".gemini": true, ".vscode": true, ".idea": true}

// safeEnv are variables that may prefix a command (VAR=x cmd) without review.
var safeEnv = map[string]bool{
	"GOFLAGS": true, "CGO_ENABLED": true, "GOOS": true, "GOARCH": true, "GOARM": true, "GOCACHE": true,
	"GOMODCACHE": true, "GOPROXY": true, "GOTOOLCHAIN": true, "GOWORK": true, "GOTESTFLAGS": true,
	"NODE_ENV": true, "CI": true, "TERM": true, "LANG": true, "LC_ALL": true, "TZ": true, "DEBUG": true,
	"RUST_LOG": true, "RUST_BACKTRACE": true, "CARGO_TERM_COLOR": true, "PYTHONUNBUFFERED": true,
	"PYTHONDONTWRITEBYTECODE": true, "NO_COLOR": true, "FORCE_COLOR": true, "COLUMNS": true, "VERBOSE": true,
}

// binDirs are where a command named by absolute path is still the plain command.
var binDirs = map[string]bool{"/bin": true, "/usr/bin": true, "/usr/local/bin": true, "/sbin": true, "/usr/sbin": true}

var hijackVars = map[string]bool{
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true, "BASH_ENV": true, "ENV": true,
	"PATH": true, "PROMPT_COMMAND": true, "IFS": true, "SHELLOPTS": true, "BASHOPTS": true,
	"GIT_SSH": true, "GIT_SSH_COMMAND": true, "GIT_EXEC_PATH": true, "GIT_CONFIG": true,
	"GIT_CONFIG_GLOBAL": true, "GIT_CONFIG_SYSTEM": true, "GIT_CONFIG_PARAMETERS": true,
	"GIT_CONFIG_COUNT": true, "GIT_ASKPASS": true, "GIT_EDITOR": true, "GIT_PAGER": true,
	"PAGER": true, "EDITOR": true, "VISUAL": true, "PYTHONSTARTUP": true, "PYTHONPATH": true,
	"CDPATH": true, "LESSOPEN": true, "LESSCLOSE": true, "MANPAGER": true, "GIT_EXTERNAL_DIFF": true,
	"SSH_ASKPASS": true, "SUDO_ASKPASS": true, "BROWSER": true, "TAR_OPTIONS": true, "LESS": true,
	"NODE_OPTIONS": true, "PERL5OPT": true, "RUBYOPT": true, "DYLD_INSERT_LIBRARIES": true,
}

// Words that are denied wherever they appear in a command line.
var blockedHosts = []string{"169.254.169.254", "metadata.google.internal", "fd00:ec2::254", "100.100.100.200"}
var bypassFlags = []string{"--dangerously-skip-permissions", "--dangerously-bypass-approvals-and-sandbox", "--yolo", "bypassPermissions"}

// Commands whose operands are files they only read. The int is how many leading
// operands are not files (a grep pattern, an awk program) unless a flag supplies them.
var readOnly = map[string]int{
	"cat": 0, "tac": 0, "head": 0, "tail": 0, "less": 0, "more": 0, "wc": 0, "nl": 0, "od": 0,
	"hexdump": 0, "strings": 0, "file": 0, "stat": 0, "du": 0, "df": 0, "ls": 0, "tree": 0,
	"realpath": 0, "readlink": 0, "cmp": 0, "diff": 0, "comm": 0, "cut": 0, "paste": 0,
	"join": 0, "rev": 0, "column": 0, "fold": 0, "fmt": 0, "md5sum": 0, "sha1sum": 0,
	"sha256sum": 0, "sha512sum": 0, "b2sum": 0, "cksum": 0, "sum": 0, "base64": 0,
	"zcat": 0, "bzcat": 0, "xzcat": 0, "zstdcat": 0, "lsattr": 0, "getfacl": 0, "namei": 0,
	"grep": 1, "egrep": 1, "fgrep": 1, "rg": 1, "ag": 1, "ack": 1, "jq": 1, "gojq": 1,
	"awk": 1, "gawk": 1, "mawk": 1, "sed": 1,
	"sort": 0, "uniq": 0, "xxd": 0, "yq": 1, "date": 0,
}

// Commands that touch no files at all.
var noFiles = map[string]bool{
	"echo": true, "printf": true, "true": true, "false": true, "test": true, "[": true,
	"seq": true, "sleep": true, "expr": true, "basename": true, "dirname": true,
	"which": true, "whereis": true, "type": true, "pwd": true, "whoami": true, "id": true,
	"groups": true, "uname": true, "hostname": true, "nproc": true, "free": true, "uptime": true,
	"ps": true, "locale": true, "getconf": true, "arch": true, "tty": true, "tr": true,
	"yes": true, "wait": true, ":": true, "set": true,
	"shopt": true, "umask": true, "ulimit": true, "unset": true, "export": true, "local": true,
	"readonly": true, "declare": true, "typeset": true, "shift": true, "return": true,
	"exit": true, "break": true, "continue": true, "read": true, "getopts": true, "jobs": true,
	"bg": true, "fg": true, "disown": true,
}

// Commands that create, change or delete their operands.
var mutating = map[string]bool{
	"mkdir": true, "touch": true, "cp": true, "mv": true, "rm": true, "rmdir": true, "ln": true,
	"chmod": true, "truncate": true, "tee": true, "install": true, "unlink": true, "mkfifo": true,
	"patch": true, "gzip": true, "gunzip": true, "xz": true, "unxz": true, "bzip2": true,
	"bunzip2": true, "zstd": true, "unzstd": true, "zip": true, "unzip": true, "tar": true,
	"dos2unix": true, "unix2dos": true,
}

// Commands denied outright, with the reason shown to the agent.
var denied = map[string]string{
	"sudo": "escalates privileges", "su": "escalates privileges", "doas": "escalates privileges",
	"pkexec": "escalates privileges", "run0": "escalates privileges",
	"eval": "evaluates a string as code, which cannot be inspected",
	"dd":   "writes raw data to devices or files", "shred": "irreversibly destroys file contents",
	"wipefs": "erases filesystem signatures", "fdisk": "changes disk partitions", "sfdisk": "changes disk partitions",
	"cfdisk": "changes disk partitions", "parted": "changes disk partitions", "sgdisk": "changes disk partitions",
	"gdisk": "changes disk partitions", "mkswap": "formats a device", "swapon": "changes system swap",
	"swapoff": "changes system swap", "mount": "changes mounted filesystems", "umount": "changes mounted filesystems",
	"losetup": "changes loop devices", "cryptsetup": "changes encrypted devices",
	"reboot": "reboots the machine", "shutdown": "shuts the machine down", "poweroff": "shuts the machine down",
	"halt": "shuts the machine down", "init": "changes the system runlevel", "telinit": "changes the system runlevel",
	"at": "schedules a job", "batch": "schedules a job", "useradd": "changes system users",
	"userdel": "changes system users", "usermod": "changes system users", "passwd": "changes passwords",
	"chpasswd": "changes passwords", "groupadd": "changes system groups", "visudo": "changes sudo rules",
	"iptables": "changes the firewall", "ip6tables": "changes the firewall", "nft": "changes the firewall",
	"ufw": "changes the firewall", "firewall-cmd": "changes the firewall", "insmod": "loads kernel modules",
	"rmmod": "unloads kernel modules", "modprobe": "loads kernel modules", "sysctl": "changes kernel settings",
	"nc": "opens raw network connections", "ncat": "opens raw network connections",
	"netcat": "opens raw network connections", "socat": "opens raw network connections",
	"telnet": "opens raw network connections", "chattr": "changes file attributes",
	"setcap": "grants file capabilities",
}

// Interpreters that run code from an argument, a file or stdin.
var interpreters = map[string]bool{
	"python": true, "python3": true, "python2": true, "node": true, "nodejs": true, "deno": true,
	"bun": true, "ruby": true, "perl": true, "php": true, "lua": true, "luajit": true,
	"Rscript": true, "julia": true, "tclsh": true, "osascript": true, "pwsh": true,
}

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true, "fish": true, "busybox": true}

var agents = map[string]bool{"agy": true, "claude": true, "codex": true, "gemini": true, "aider": true, "opencode": true, "goose": true, "cursor-agent": true, "amp": true}

// exec judges one simple command. args[0] is the command name.
func (w *walker) exec(args []arg, depth int) {
	if depth > maxDepth {
		w.r.denyf("nests shells or wrappers too deeply to inspect")
		return
	}
	if len(args) == 0 {
		return
	}
	a0 := args[0]
	if a0.kind == dynamic {
		w.r.denyf("runs a command whose name is computed at run time")
		return
	}
	name := a0.v
	if strings.IndexByte(name, '/') >= 0 {
		if !binDirs[filepath.Dir(name)] {
			w.read(a0)
			w.r.judgef("runs a program by path: " + name)
			return
		}
		name = filepath.Base(name)
	}
	for _, a := range args {
		for _, h := range blockedHosts {
			if strings.Contains(a.v, h) {
				w.r.denyf("contacts a cloud metadata endpoint")
				return
			}
		}
		for _, f := range bypassFlags {
			if strings.Contains(a.v, f) {
				w.r.denyf("disables another tool's permission checks (" + f + ")")
				return
			}
		}
		if strings.Contains(a.v, "/dev/tcp/") || strings.Contains(a.v, "/dev/udp/") {
			w.r.denyf("opens a raw network connection through /dev/tcp or /dev/udp")
			return
		}
	}
	rest := args[1:]
	if name != "find" {
		for _, a := range rest {
			if runsProgram(a.v) {
				w.r.judgef(name + " " + a.v + " makes it run another program")
				break
			}
		}
	}

	if why, ok := denied[name]; ok {
		w.r.denyf(name + " " + why)
		return
	}
	if strings.HasPrefix(name, "mkfs") || strings.HasPrefix(name, "mke2fs") {
		w.r.denyf(name + " formats a filesystem")
		return
	}
	switch {
	case noFiles[name]:
		if name == "export" || name == "declare" || name == "typeset" || name == "local" || name == "readonly" {
			for _, a := range rest {
				if n, _, ok := strings.Cut(a.v, "="); ok && hijackVars[n] {
					w.r.denyf("sets " + n + ", which changes what programs run")
				}
			}
		}
		return
	case readOnly[name] > 0 || isReadOnly(name):
		w.readCmd(name, rest)
		return
	case mutating[name]:
		w.mutate(name, rest)
		return
	case interpreters[name] || strings.HasPrefix(name, "python3."):
		w.interp(name, rest)
		return
	case shells[name]:
		w.shell(name, rest, depth)
		return
	case agents[name]:
		w.r.judgef("starts another AI agent: " + name)
		return
	}

	switch name {
	case "cd":
		w.cd(rest)
	case "pushd", "popd":
		w.e.cwd = ""
	case "env":
		w.env(rest, depth)
	case "printenv":
		w.r.judgef("prints environment variables, which may hold secrets")
	case "nohup", "setsid", "time", "builtin", "unbuffer", "caffeinate":
		w.exec(skipFlags(rest, ""), depth+1)
	case "nice":
		w.exec(skipFlags(rest, "n"), depth+1)
	case "ionice":
		w.exec(skipFlags(rest, "cnp"), depth+1)
	case "stdbuf":
		w.exec(skipFlags(rest, "ioe"), depth+1)
	case "timeout":
		if in := skipFlags(rest, "sk"); len(in) > 0 {
			w.exec(in[1:], depth+1) // drop DURATION
		}
	case "chrt", "taskset":
		if in := skipFlags(rest, ""); len(in) > 0 {
			w.exec(in[1:], depth+1) // drop priority / mask
		}
	case "command":
		if len(rest) > 0 && (rest[0].v == "-v" || rest[0].v == "-V") {
			return
		}
		w.exec(skipFlags(rest, ""), depth+1)
	case "exec":
		w.exec(skipFlags(rest, "a"), depth+1)
	case "xargs":
		w.xargs(rest, depth)
	case "find":
		w.find(rest, depth)
	case "source", ".":
		w.source(rest)
	case "alias":
		for _, a := range rest {
			if strings.Contains(a.v, "=") {
				w.r.denyf("defines an alias, which hides what later commands run")
				return
			}
		}
	case "trap":
		if len(rest) > 1 {
			w.r.judgef("installs a trap handler")
		}
	case "kill", "pkill", "killall":
		for _, a := range rest {
			if strings.Contains(a.v, "agy") {
				w.r.denyf("kills the agent or its gate")
				return
			}
		}
		w.r.judgef("sends signals to processes")
	case "chown", "chgrp":
		w.r.judgef("changes file ownership")
		w.paths(rest, "changes ownership of")
	case "crontab":
		if len(rest) == 1 && rest[0].v == "-l" {
			return
		}
		w.r.denyf("changes scheduled jobs (crontab)")
	case "systemctl", "service", "launchctl":
		w.service(name, rest)
	case "git":
		w.git(rest)
	case "go", "gofmt", "cargo", "rustc", "npm", "pnpm", "yarn", "npx", "make", "pytest", "py.test",
		"tsc", "eslint", "prettier", "shellcheck", "golangci-lint", "staticcheck", "helm", "terraform",
		"docker", "podman", "kubectl", "gh":
		w.build(name, rest)
	case "curl", "wget", "http", "https", "xh", "aria2c":
		w.fetch(name, rest)
	case "ssh", "scp", "sftp", "rsync":
		w.r.judgef(name + " connects to another machine")
	case "aws", "gcloud", "az", "flyctl", "fly", "vercel", "netlify", "heroku", "firebase", "wrangler", "doctl", "pulumi", "eksctl", "serverless", "sls":
		w.cloud(name, rest)
	default:
		w.r.judgef("runs " + name + ", which the rules do not know")
	}
}

// runsProgram reports options that make an otherwise harmless command run
// another program or load code: tar --to-command, sort --compress-program,
// go build -toolexec, go test -exec, git grep -O, rg --pre and the like.
func runsProgram(v string) bool {
	if len(v) < 2 || v[0] != '-' {
		return false
	}
	name, _, _ := strings.Cut(strings.ToLower(v), "=")
	if strings.HasPrefix(name, "--no-") {
		return false // switches something off
	}
	for _, s := range []string{"exec", "command", "pager", "program", "toolexec", "vettool", "hook", "editor",
		"checkpoint-action", "upload-pack", "receive-pack", "ext-diff", "textconv", "overlay", "config",
		"plugin", "rcfile", "init-file"} {
		if strings.Contains(name, s) {
			return true
		}
	}
	return name == "--pre"
}

func isReadOnly(name string) bool { _, ok := readOnly[name]; return ok }

// skipFlags drops leading options of a wrapper. Letters in withValue name
// single-letter flags that consume the next word (-n 10).
func skipFlags(args []arg, withValue string) []arg {
	for i := 0; i < len(args); i++ {
		v := args[i].v
		switch {
		case v == "--":
			return args[i+1:]
		case len(v) < 2 || v[0] != '-' || args[i].kind == dynamic:
			return args[i:]
		case len(v) == 2 && strings.IndexByte(withValue, v[1]) >= 0:
			i++
		}
	}
	return nil
}

// operands splits args into non-option operands, honouring -- and the flags
// in withValue ("-e,-f,--regexp") that take the next word as their value.
func operands(args []arg, withValue string) (ops, vals []arg) {
	for i := 0; i < len(args); i++ {
		v := args[i].v
		switch {
		case v == "--":
			return append(ops, args[i+1:]...), vals
		case len(v) > 1 && v[0] == '-' && args[i].kind != dynamic:
			if _, after, ok := strings.Cut(v, "="); ok && strings.HasPrefix(v, "--") {
				vals = append(vals, arg{v: after, kind: args[i].kind})
			} else if withValue != "" && hasFlag(withValue, v) && i+1 < len(args) {
				i++
				vals = append(vals, args[i])
			} else if v[1] != '-' && len(v) > 2 && hasFlag(withValue, v[:2]) {
				vals = append(vals, arg{v: v[2:], kind: args[i].kind}) // -tDIR
			}
		default:
			ops = append(ops, args[i])
		}
	}
	return ops, vals
}

func hasFlag(list, f string) bool {
	for list != "" {
		var x string
		x, list, _ = strings.Cut(list, ",")
		if x == f {
			return true
		}
	}
	return false
}

func has(args []arg, flags ...string) bool {
	for _, a := range args {
		for _, f := range flags {
			if a.v == f {
				return true
			}
		}
	}
	return false
}

// hasShort reports whether a bundled short option like -rf contains letter c.
func hasShort(args []arg, c byte) bool {
	for _, a := range args {
		if len(a.v) > 1 && a.v[0] == '-' && a.v[1] != '-' && strings.IndexByte(a.v[1:], c) >= 0 {
			return true
		}
	}
	return false
}

func (w *walker) paths(args []arg, what string) {
	for _, a := range args {
		w.write(a, what)
	}
}

func (w *walker) cd(rest []arg) {
	ops, _ := operands(rest, "")
	switch {
	case len(ops) == 0:
		w.e.cwd = w.e.home
	case ops[0].kind != static || ops[0].v == "-":
		w.e.cwd = ""
	default:
		if a, ok := w.e.abs(ops[0].v); ok {
			w.e.cwd = realpath(a)
		} else {
			w.e.cwd = ""
		}
	}
}

func (w *walker) readCmd(name string, rest []arg) {
	valueFlags := "-e,-f,--regexp,--file,-m,-A,-B,-C,-n,-c,-t,-g,--glob,--type,-T,-d,--max-count"
	skip := readOnly[name]
	switch name {
	case "rg":
		if has(rest, "--pre") || hasPrefix(rest, "--pre=") {
			w.r.judgef("rg --pre runs a program on each file")
		}
	case "sed":
		w.sed(rest)
		return
	case "awk", "gawk", "mawk":
		if has(rest, "-f", "--file") || hasPrefix(rest, "--file=") {
			w.r.judgef("awk runs a program file")
			return
		}
		if ops, _ := operands(rest, "-f,-v,-F"); len(ops) > 0 && !awkSafe(ops[0].v) {
			w.r.judgef("awk program may run commands or write files")
		}
		valueFlags = "-f,-v,-F"
	case "sort":
		if _, vals := operands(rest, "-o,--output,-T,-S,-k,-t"); len(vals) > 0 {
			for i, a := range rest {
				if (a.v == "-o" || a.v == "--output") && i+1 < len(rest) {
					w.write(rest[i+1], "writes")
				} else if strings.HasPrefix(a.v, "--output=") {
					w.write(arg{v: a.v[len("--output="):], kind: a.kind}, "writes")
				}
			}
		}
		valueFlags = "-o,--output,-T,-S,-k,-t"
	case "yq":
		if has(rest, "-i", "--inplace") {
			ops, _ := operands(rest, "")
			if len(ops) > 1 {
				w.paths(ops[1:], "edits")
			}
			return
		}
	}
	if (skip > 0) && (has(rest, "-e", "-f", "--regexp", "--file") || hasPrefix(rest, "--regexp=")) && name != "awk" && name != "jq" {
		skip = 0
	}
	// Options whose value is a file the command reads.
	for i, a := range rest {
		switch {
		case (a.v == "-f" || a.v == "--file" || a.v == "-r" || a.v == "--reference" || a.v == "--rawfile" || a.v == "--slurpfile") && i+1 < len(rest):
			if a.v == "--rawfile" || a.v == "--slurpfile" {
				if i+2 < len(rest) {
					w.read(rest[i+2])
				}
				continue
			}
			w.read(rest[i+1])
		case strings.HasPrefix(a.v, "--file=") || strings.HasPrefix(a.v, "--reference="):
			_, f, _ := strings.Cut(a.v, "=")
			w.read(arg{v: f, kind: a.kind})
		}
	}
	ops, _ := operands(rest, valueFlags)
	recursive := name == "rg" || name == "ag" || name == "ack" || has(rest, "-r", "-R", "--recursive") || (strings.HasPrefix(name, "grep") || name == "egrep" || name == "fgrep") && (hasShort(rest, 'r') || hasShort(rest, 'R'))
	if recursive {
		for i, a := range ops {
			if i >= skip && a.kind == static {
				if z := w.e.zoneOf(globBase(a)); z != zoneWorkspace && z != zoneScratch {
					w.r.judgef(name + " searches recursively outside the workspace: " + a.v)
				}
			}
		}
	}
	for i, a := range ops {
		switch {
		case i < skip:
			continue
		case (name == "uniq" || name == "xxd") && i == 1:
			w.write(a, "writes")
		default:
			w.read(a)
		}
	}
}

func hasPrefix(args []arg, p string) bool {
	for _, a := range args {
		if strings.HasPrefix(a.v, p) {
			return true
		}
	}
	return false
}

// mutateValueFlags lists, per command, the options that take the next word as a value.
var mutateValueFlags = map[string]string{
	"cp": "-t,--target-directory,-S,--suffix", "mv": "-t,--target-directory,-S,--suffix",
	"ln": "-t,--target-directory,-S,--suffix", "install": "-t,--target-directory,-S,--suffix,-m,--mode,-o,--owner,-g,--group",
	"mkdir": "-m,--mode", "truncate": "-s,--size,-r,--reference", "chmod": "--reference",
	"tar": "-C,--directory,-f,--file,-T,--files-from,-X,--exclude-from", "unzip": "-d,-x", "zip": "-x,-i",
	"patch": "-p,-i,--input,-o,--output,-d,--directory,-B,-r", "touch": "-d,--date,-r,--reference,-t",
}

func (w *walker) mutate(name string, rest []arg) {
	ops, vals := operands(rest, mutateValueFlags[name])
	switch name {
	case "rm", "rmdir", "unlink":
		recursive := has(rest, "--recursive") || hasShort(rest, 'r') || hasShort(rest, 'R')
		for _, a := range ops {
			p := globBase(a)
			if a.kind == dynamic {
				w.r.judgef("deletes a path built from expansions")
				continue
			}
			if recursive && w.e.isRootOrAbove(p) {
				w.r.denyf("recursively deletes " + p + ", which contains the workspace, home or root")
				return
			}
			switch w.e.zoneOf(p) {
			case zoneOutside, zoneUnknown:
				if recursive {
					w.r.denyf("recursively deletes outside the workspace: " + p)
					return
				}
				w.r.judgef("deletes outside the workspace: " + p)
			default:
				w.write(a, "deletes")
			}
		}
		return
	case "chmod":
		if len(ops) > 0 && setuidMode(ops[0].v) {
			w.r.denyf("sets setuid or setgid bits")
			return
		}
		if len(ops) > 0 {
			ops = ops[1:]
		}
	case "cp", "mv", "install", "ln":
		// Sources are read, the last operand (or -t DIR) is written.
		target := -1
		if !has(rest, "-t", "--target-directory") && !hasPrefix(rest, "--target-directory=") {
			target = len(ops) - 1
		}
		for i, a := range ops {
			if i == target || name == "mv" {
				w.write(a, "writes")
			} else {
				w.read(a) // for ln, linking to a protected file has no legitimate use
			}
		}
		for _, a := range vals {
			w.write(a, "writes")
		}
		return
	case "tar", "zip", "unzip":
		if name == "tar" && hasShort(rest, 'I') {
			w.r.judgef("tar -I runs a compression program")
			return
		}
		if name == "zip" && has(rest, "-TT") {
			w.r.judgef("zip -TT runs a test command")
			return
		}
		for _, a := range append(ops, vals...) {
			w.write(a, "archives or extracts into")
		}
		return
	}
	w.paths(ops, "writes")
	for _, a := range vals {
		if strings.ContainsAny(a.v, "/~.") {
			w.write(a, "writes")
		}
	}
}

func setuidMode(m string) bool {
	if isDigits(m) && len(m) == 4 {
		return m[0] != '0'
	}
	return strings.ContainsRune(m, 's') || strings.ContainsRune(m, 't') && strings.ContainsRune(m, '+')
}

func (w *walker) env(rest []arg, depth int) {
	i := 0
	for ; i < len(rest); i++ {
		v := rest[i].v
		switch {
		case v == "--":
			i++
			goto run
		case v == "-u" || v == "--unset":
			i++
		case v == "-C" || v == "--chdir":
			if i+1 < len(rest) {
				i++
				w.cd(rest[i : i+1])
			}
		case strings.HasPrefix(v, "--chdir="):
			w.cd([]arg{{v: v[len("--chdir="):], kind: rest[i].kind}})
		case strings.HasPrefix(v, "-C") && len(v) > 2:
			w.cd([]arg{{v: v[2:], kind: rest[i].kind}})
		case v == "-S" || strings.HasPrefix(v, "--split-string") || strings.HasPrefix(v, "-S"):
			w.r.judgef("env -S splits a string into a command")
			return
		case len(v) > 1 && v[0] == '-':
		case strings.Contains(v, "="):
			if n, _, _ := strings.Cut(v, "="); hijackVars[n] {
				w.r.denyf("sets " + n + ", which changes what programs run")
				return
			}
		default:
			goto run
		}
	}
run:
	if i < len(rest) {
		w.exec(rest[i:], depth+1)
		return
	}
	w.r.judgef("prints environment variables, which may hold secrets")
}

func (w *walker) xargs(rest []arg, depth int) {
	i := 0
	for ; i < len(rest); i++ {
		v := rest[i].v
		if v == "--" {
			i++
			break
		}
		if len(v) < 2 || v[0] != '-' {
			break
		}
		if len(v) == 2 && strings.IndexByte("EeILnPsda", v[1]) >= 0 {
			i++
		}
	}
	if i >= len(rest) {
		return // bare xargs echoes its input
	}
	// The inner command receives operands from stdin, which are unknown.
	inner := append(append([]arg{}, rest[i:]...), arg{kind: dynamic})
	w.exec(inner, depth+1)
}

func (w *walker) find(rest []arg, depth int) {
	var starts []arg
	i := 0
	for ; i < len(rest) && !isFindExpr(rest[i].v); i++ {
		if rest[i].v == "-H" || rest[i].v == "-L" || rest[i].v == "-P" {
			continue
		}
		starts = append(starts, rest[i])
	}
	if len(starts) == 0 {
		starts = []arg{{v: "."}}
	}
	for _, s := range starts {
		w.read(s)
		if s.kind == static {
			if z := w.e.zoneOf(globBase(s)); z != zoneWorkspace && z != zoneScratch {
				w.r.judgef("find searches outside the workspace: " + s.v)
			}
		}
	}
	// {} stands for something below each start path.
	child := func(s arg) arg {
		if s.kind != static {
			return arg{kind: dynamic}
		}
		return arg{v: filepath.Join(s.v, "_")}
	}
	for ; i < len(rest); i++ {
		switch v := rest[i].v; v {
		case "-delete":
			for _, s := range starts {
				w.exec([]arg{{v: "rm"}, {v: "-r"}, child(s)}, depth+1)
			}
		case "-exec", "-execdir", "-ok", "-okdir":
			j := i + 1
			for j < len(rest) && rest[j].v != ";" && rest[j].v != "+" {
				j++
			}
			for _, s := range starts {
				inner := make([]arg, 0, j-i-1)
				for _, a := range rest[i+1 : j] {
					if a.v == "{}" {
						a = child(s)
					}
					inner = append(inner, a)
				}
				w.exec(inner, depth+1)
			}
			i = j
		case "-fprint", "-fprint0", "-fprintf", "-fls":
			if i+1 < len(rest) {
				i++
				w.write(rest[i], "writes")
			}
		}
	}
}

func isFindExpr(v string) bool {
	return len(v) > 0 && (v[0] == '-' || v == "(" || v == ")" || v == "!" || v == ",")
}

func (w *walker) source(rest []arg) {
	if len(rest) == 0 {
		return
	}
	a := rest[0]
	w.read(a)
	if a.kind == static && w.e.zoneOf(a.v) == zoneWorkspace {
		w.r.judgef("sources a workspace script: " + a.v)
		return
	}
	w.r.denyf("sources a script from outside the workspace")
}

// shell handles sh/bash -c 'script' by inspecting the script itself.
func (w *walker) shell(name string, rest []arg, depth int) {
	if name == "busybox" {
		if len(rest) > 0 {
			w.exec(rest, depth+1)
		}
		return
	}
	for i := 0; i < len(rest); i++ {
		v := rest[i].v
		switch {
		case v == "-c" || (len(v) > 2 && v[0] == '-' && v[1] != '-' && strings.HasSuffix(v, "c")):
			if i+1 >= len(rest) {
				return
			}
			if rest[i+1].kind != static {
				w.r.denyf("runs a shell string built at run time")
				return
			}
			sub := w.fork()
			sub.depth = w.depth + depth + 1
			sub.script(rest[i+1].v)
			return
		case v == "-o" || v == "+o" || v == "-O" || v == "+O" || v == "--rcfile" || v == "--init-file":
			i++
		case v == "-s" || v == "-":
			w.stdinScript(name)
			return
		case len(v) > 1 && (v[0] == '-' || v[0] == '+'):
		default:
			if rest[i].kind == dynamic {
				w.r.denyf(name + " runs a script produced at run time")
				return
			}
			w.read(rest[i])
			w.r.judgef("runs a shell script: " + v)
			return
		}
	}
	w.stdinScript(name)
}

func (w *walker) stdinScript(name string) {
	switch w.stdin {
	case fromPipe:
		w.r.denyf("pipes data into " + name + ", which runs it as code")
	case fromHeredoc:
		if w.here == "" {
			w.r.judgef("feeds a dynamic heredoc to " + name)
			return
		}
		sub := w.fork()
		sub.depth++
		sub.script(w.here)
	default:
		w.r.judgef("starts an interactive " + name)
	}
}

func (w *walker) interp(name string, rest []arg) {
	if has(rest, "--version", "-V", "--help") && len(rest) == 1 {
		return
	}
	if (name == "python" || strings.HasPrefix(name, "python3") || name == "python3") && len(rest) >= 2 && rest[0].v == "-m" {
		if rest[1].v == "pytest" || rest[1].v == "unittest" {
			w.checkBuildPaths(rest[2:])
			return
		}
		w.r.judgef(name + " -m " + rest[1].v + " runs a module")
		return
	}
	ops, _ := operands(rest, "-W,-X,-r,-I")
	switch {
	case has(rest, "-c", "-e", "--eval", "-p", "--print", "-E"):
		w.r.judgef(name + " runs inline code")
	case len(ops) == 0 || ops[0].v == "-":
		if w.stdin == fromPipe {
			w.r.denyf("pipes data into " + name + ", which runs it as code")
			return
		}
		w.r.judgef(name + " runs code from stdin")
	default:
		w.read(ops[0])
		w.r.judgef(name + " runs the script " + ops[0].v)
	}
}

func (w *walker) service(name string, rest []arg) {
	ops, _ := operands(rest, "")
	if len(ops) > 0 {
		switch ops[0].v {
		case "status", "show", "list-units", "list-unit-files", "list-timers", "is-active", "is-enabled", "is-failed", "cat":
			return
		}
	}
	w.r.denyf(name + " changes system services")
}

func (w *walker) fetch(name string, rest []arg) {
	for i, a := range rest {
		v := a.v
		switch {
		case v == "-d" || strings.HasPrefix(v, "--data") || v == "--json" || v == "-F" || v == "--form" ||
			strings.HasPrefix(v, "--form-") || v == "-T" || v == "--upload-file" || v == "-K" || v == "--config" ||
			strings.HasPrefix(v, "--post-") || strings.HasPrefix(v, "--body-"):
			w.r.denyf(name + " sends data to a remote server; ask the user first")
			return
		case (v == "-X" || v == "--request" || v == "--method") && i+1 < len(rest):
			if m := strings.ToUpper(rest[i+1].v); m != "GET" && m != "HEAD" && m != "OPTIONS" {
				w.r.denyf(name + " makes a " + m + " request; ask the user first")
				return
			}
		case strings.HasPrefix(v, "--method="):
			if m := strings.ToUpper(v[len("--method="):]); m != "GET" && m != "HEAD" {
				w.r.denyf(name + " makes a " + m + " request; ask the user first")
				return
			}
		case strings.HasPrefix(v, "@") && i > 0:
			w.r.denyf(name + " uploads a local file")
			return
		case (v == "-o" || v == "--output" || v == "-O" || v == "--output-document") && i+1 < len(rest) && rest[i+1].v != "-":
			w.write(rest[i+1], "downloads into")
		}
		if a.kind == dynamic && !strings.HasPrefix(v, "-") {
			w.r.judgef(name + " uses a URL or argument built from expansions")
		}
	}
	w.r.judgef(name + " fetches from the network")
}

func (w *walker) cloud(name string, rest []arg) {
	for _, a := range rest {
		switch v := a.v; {
		case v == "deploy" || v == "delete" || v == "destroy" || v == "rm" || v == "rb" || v == "up" ||
			v == "publish" || v == "apply" || v == "terminate-instances" || strings.HasPrefix(v, "delete-") || strings.HasPrefix(v, "put-"):
			w.r.denyf(name + " " + v + " changes cloud resources")
			return
		}
	}
	w.r.judgef(name + " talks to a cloud provider")
}

// build covers build, test and project tooling. Commands that only build and
// test inside the workspace are allowed; publishing and deploying are denied.
func (w *walker) build(name string, rest []arg) {
	sub := ""
	if ops, _ := operands(rest, "-C,-f,-j,-o,-n,--manifest-path,--prefix"); len(ops) > 0 {
		sub = ops[0].v
	}
	deny := func(why string) { w.r.denyf(name + " " + sub + " " + why) }
	judge := func() { w.r.judgef(name + " " + sub + " is not a known build or test step") }
	switch name {
	case "go":
		switch sub {
		case "build", "test", "vet", "fmt", "list", "version", "doc", "help", "mod", "work", "clean", "bug":
		case "env":
			if has(rest, "-w", "-u") {
				judge()
				return
			}
		default:
			judge()
			return
		}
	case "cargo":
		switch sub {
		case "build", "b", "check", "c", "test", "t", "clippy", "fmt", "doc", "bench", "metadata", "tree", "version", "clean", "fetch":
		case "publish", "login", "logout", "owner", "yank":
			deny("publishes or changes registry state")
			return
		default:
			judge()
			return
		}
	case "npm", "pnpm", "yarn":
		switch sub {
		case "test", "t", "ci", "ls", "list", "outdated", "audit", "why", "explain", "version", "":
			if sub == "audit" && has(rest, "fix") {
				judge()
				return
			}
		case "install", "i", "add":
			if ops, _ := operands(rest, ""); len(ops) > 1 || sub == "add" {
				w.r.judgef(name + " installs a new package")
				return
			}
		case "run", "run-script":
			ops, _ := operands(rest, "")
			if len(ops) < 2 || !safeScript(ops[1].v) {
				judge()
				return
			}
		case "publish", "unpublish", "deprecate", "owner", "login", "adduser", "logout", "token", "dist-tag", "access", "npm":
			deny("publishes or changes registry state")
			return
		default:
			judge()
			return
		}
	case "npx":
		w.r.judgef("npx downloads and runs a package")
		return
	case "make":
		ops, _ := operands(rest, "-C,-f,-j,-l,-o,-W,-I")
		for _, t := range ops {
			if strings.Contains(t.v, "=") || !safeScript(t.v) {
				w.r.judgef("make target or variable is not a known build step: " + t.v)
				return
			}
		}
		if has(rest, "-f", "--file", "--makefile") {
			w.r.judgef("make runs a non-default makefile")
			return
		}
	case "helm":
		switch sub {
		case "lint", "template", "version", "show", "dependency":
		case "install", "upgrade", "uninstall", "delete", "push", "rollback":
			deny("changes a cluster or registry")
			return
		default:
			judge()
			return
		}
	case "terraform":
		switch sub {
		case "fmt", "validate", "version":
		case "apply", "destroy", "import", "taint", "untaint":
			deny("changes real infrastructure")
			return
		default:
			judge()
			return
		}
	case "docker", "podman":
		switch sub {
		case "push", "login":
			deny("publishes images or stores credentials")
			return
		}
		judge()
		return
	case "kubectl":
		switch sub {
		case "apply", "create", "delete", "patch", "replace", "scale", "rollout", "edit", "set", "label",
			"annotate", "drain", "cordon", "uncordon", "taint", "exec", "cp", "run", "expose", "autoscale":
			deny("changes a Kubernetes cluster")
			return
		}
		judge()
		return
	case "gh":
		ops, _ := operands(rest, "-R,--repo")
		if len(ops) >= 2 {
			switch ops[0].v + " " + ops[1].v {
			case "repo delete", "repo archive", "release delete", "secret set", "secret delete", "auth login",
				"auth token", "auth logout", "ssh-key add", "ssh-key delete", "gpg-key add", "variable set":
				deny("changes repositories, secrets or credentials")
				return
			}
		}
		w.r.judgef("gh talks to GitHub")
		return
	}
	// Allowed build step: it must run inside the workspace and write nowhere else.
	if w.e.cwd == "" || w.e.zoneOf(w.e.cwd) != zoneWorkspace {
		w.r.judgef(name + " runs outside the workspace")
		return
	}
	w.checkBuildPaths(rest)
}

// safeScript lists script and make target names that build, test or lint.
func safeScript(s string) bool {
	switch s {
	case "all", "build", "test", "tests", "check", "lint", "fmt", "format", "vet", "typecheck", "type-check",
		"clean", "bench", "coverage", "compile", "dev-build", "test:unit", "test:ci", "ci":
		return true
	}
	return false
}

func (w *walker) checkBuildPaths(rest []arg) {
	for i, a := range rest {
		v := a.v
		if (v == "-o" || v == "--output" || v == "--out-dir" || v == "--target-dir" || v == "-C") && i+1 < len(rest) {
			w.write(rest[i+1], "builds into")
			continue
		}
		if a.kind == dynamic {
			w.r.judgef("build argument built from expansions")
			continue
		}
		if _, after, ok := strings.Cut(v, "="); ok && strings.HasPrefix(v, "-") {
			v = after
		}
		if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.HasPrefix(v, "..") {
			w.read(arg{v: v, kind: a.kind})
		}
	}
}

// git ------------------------------------------------------------------------

func (w *walker) git(rest []arg) {
	i := 0
	for ; i < len(rest); i++ {
		v := rest[i].v
		switch {
		case v == "-C" && i+1 < len(rest):
			i++
			w.cd(rest[i : i+1])
		case v == "-c" && i+1 < len(rest):
			i++
			if k, _, _ := strings.Cut(rest[i].v, "="); rest[i].kind != static || gitConfigRuns(k) {
				w.r.denyf("git -c sets " + k + ", which can run commands")
				return
			}
		case strings.HasPrefix(v, "--git-dir") || strings.HasPrefix(v, "--work-tree") || strings.HasPrefix(v, "--exec-path") || strings.HasPrefix(v, "--config-env"):
			w.r.judgef("git uses a custom repository location or config: " + v)
			return
		case v == "--no-pager" || v == "-P" || v == "-p" || v == "--paginate" || v == "--bare" || v == "--no-replace-objects" ||
			v == "--no-optional-locks" || strings.HasSuffix(v, "-pathspecs"):
		case strings.HasPrefix(v, "-"):
			w.r.judgef("git option the rules do not know: " + v)
			return
		default:
			goto sub
		}
	}
	return // bare `git` prints help
sub:
	sub, args := rest[i].v, rest[i+1:]
	if rest[i].kind != static {
		w.r.denyf("runs a git subcommand built at run time")
		return
	}
	for j, a := range args {
		if a.v == "--output" && j+1 < len(args) {
			w.write(args[j+1], "writes")
		} else if strings.HasPrefix(a.v, "--output=") {
			w.write(arg{v: a.v[len("--output="):], kind: a.kind}, "writes")
		}
	}
	if sub == "grep" && (has(args, "-O") || hasPrefix(args, "-O")) {
		w.r.judgef("git grep -O opens results in a program")
		return
	}
	inRepo := w.e.cwd != "" && w.e.zoneOf(w.e.cwd) == zoneWorkspace
	local := func() {
		if !inRepo {
			w.r.judgef("git " + sub + " changes a repository outside the workspace")
		}
	}
	switch sub {
	case "status", "log", "show", "diff", "blame", "annotate", "ls-files", "ls-tree", "grep", "rev-parse",
		"describe", "shortlog", "cat-file", "whatchanged", "name-rev", "merge-base", "for-each-ref",
		"count-objects", "version", "help", "show-ref", "var", "check-ignore", "check-attr", "diff-tree",
		"diff-files", "diff-index", "rev-list", "range-diff", "cherry", "show-branch", "verify-commit", "verify-tag", "fsck":
		if w.e.cwd != "" && w.e.zoneOf(w.e.cwd) == zoneSecret {
			w.r.denyf("reads a repository in a protected location")
		}
	case "reflog":
		if len(args) > 0 && (args[0].v == "expire" || args[0].v == "delete") {
			w.r.judgef("git reflog " + args[0].v + " discards recovery points")
			return
		}
	case "add", "commit", "switch", "mv", "rm", "init", "merge", "cherry-pick", "revert", "apply", "am",
		"format-patch", "archive", "notes", "mergetool", "difftool", "stage":
		local()
	case "branch":
		if has(args, "-d", "-D", "--delete", "-f", "--force") || hasShort(args, 'D') {
			w.r.judgef("git branch deletes or overwrites branches")
			return
		}
		local()
	case "tag":
		if has(args, "-d", "--delete", "-f", "--force") {
			w.r.judgef("git tag deletes or moves tags")
			return
		}
		local()
	case "remote":
		ops, _ := operands(args, "")
		if len(ops) == 0 || ops[0].v == "show" || ops[0].v == "get-url" {
			return
		}
		w.r.judgef("git remote changes remotes")
	case "config":
		w.gitConfig(args)
	case "stash":
		if len(args) > 0 && (args[0].v == "drop" || args[0].v == "clear") {
			w.r.judgef("git stash " + args[0].v + " discards stashed work")
			return
		}
		local()
	case "restore", "checkout":
		if sub == "restore" && has(args, "--staged", "-S") && !has(args, "--worktree", "-W") {
			local()
			return
		}
		ops, _ := operands(args, "-b,-B,--orphan,-s,--source,--conflict")
		if has(args, "-b", "-B", "--orphan") {
			local()
			return
		}
		for _, a := range ops {
			if a.v == "." || a.v == ":/" || a.v == "*" || a.kind != static {
				w.r.judgef("git " + sub + " may discard uncommitted changes")
				return
			}
		}
		if sub == "restore" && len(ops) == 0 {
			w.r.judgef("git restore without paths")
			return
		}
		if has(args, "-f", "--force", "--") && sub == "checkout" {
			w.r.judgef("git checkout may discard uncommitted changes")
			return
		}
		local()
	case "reset":
		if has(args, "--hard", "--keep", "--merge") {
			w.r.judgef("git reset " + "discards uncommitted work")
			return
		}
		local()
	case "clean":
		if has(args, "-n", "--dry-run") {
			return
		}
		w.r.judgef("git clean deletes untracked files")
	case "push":
		for _, a := range args {
			v := a.v
			if v == "-f" || v == "--force" || strings.HasPrefix(v, "--force-with-lease") || v == "--force-if-includes" ||
				v == "--mirror" || v == "--delete" || v == "-d" || v == "--prune" || v == "--all" ||
				(len(v) > 0 && v[0] == '+') || (len(v) > 1 && v[0] == ':') || (len(v) > 1 && v[0] == '-' && v[1] != '-' && strings.ContainsAny(v[1:], "fd")) {
				w.r.denyf("git push " + v + " rewrites or deletes remote history")
				return
			}
		}
		w.r.judgef("git push publishes commits to a remote")
	case "filter-branch", "filter-repo":
		w.r.denyf("git " + sub + " rewrites history")
	case "daemon", "instaweb", "credential", "credential-store", "credential-cache", "send-email", "upload-pack", "receive-pack":
		w.r.denyf("git " + sub + " exposes the repository or credentials")
	case "fetch", "pull", "clone", "ls-remote", "submodule":
		w.r.judgef("git " + sub + " uses the network")
	default:
		w.r.judgef("git " + sub + " is not a known safe git operation")
	}
}

func (w *walker) gitConfig(args []arg) {
	for _, a := range args {
		switch a.v {
		case "--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l", "--list", "--show-origin", "--show-scope", "--name-only", "--null", "-z":
			return
		case "--global", "--system", "--file", "-f", "--blob":
			w.r.denyf("git config changes configuration outside the repository")
			return
		}
	}
	ops, _ := operands(args, "")
	if len(ops) < 2 {
		return // `git config key` reads
	}
	if ops[0].kind != static || gitConfigRuns(ops[0].v) {
		w.r.denyf("git config sets " + ops[0].v + ", which can run commands")
	}
}

// gitConfigRuns reports whether a git config key makes git run a program or
// fetch from somewhere else.
func gitConfigRuns(key string) bool {
	k := strings.ToLower(key)
	for _, p := range []string{"alias.", "credential.", "filter.", "include.", "includeif.", "url.", "diff.", "merge.", "difftool.", "mergetool.", "uploadpack.", "remote.", "protocol."} {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	for _, s := range []string{".command", ".cmd", ".hook", ".helper", ".program", ".textconv", ".driver", ".path"} {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	switch k {
	case "core.sshcommand", "core.hookspath", "core.fsmonitor", "core.pager", "core.editor", "core.gitproxy",
		"core.askpass", "core.worktree", "sequence.editor", "gpg.program", "http.proxy", "https.proxy", "core.attributesfile", "core.excludesfile":
		return true
	}
	return false
}

// sed ------------------------------------------------------------------------

func (w *walker) sed(rest []arg) {
	inPlace := false
	var scripts, files []arg
	for i := 0; i < len(rest); i++ {
		v := rest[i].v
		switch {
		case v == "-e" || v == "--expression":
			if i+1 < len(rest) {
				i++
				scripts = append(scripts, rest[i])
			}
		case strings.HasPrefix(v, "--expression="):
			scripts = append(scripts, arg{v: v[len("--expression="):], kind: rest[i].kind})
		case v == "-f" || v == "--file":
			w.r.judgef("sed runs a script file")
			return
		case v == "-i" || strings.HasPrefix(v, "--in-place") || (len(v) > 1 && v[0] == '-' && v[1] != '-' && strings.IndexByte(v, 'i') >= 0):
			inPlace = true
		case v == "--":
			files = append(files, rest[i+1:]...)
			i = len(rest)
		case len(v) > 1 && v[0] == '-':
		default:
			files = append(files, rest[i])
		}
	}
	if len(scripts) == 0 && len(files) > 0 {
		scripts, files = files[:1], files[1:]
	}
	for _, s := range scripts {
		if s.kind != static || !sedSafe(s.v) {
			w.r.judgef("sed script may run commands or write files")
		}
	}
	for _, f := range files {
		if inPlace {
			w.write(f, "edits")
		} else {
			w.read(f)
		}
	}
}

// sedSafe parses a sed script and reports whether it only edits the stream:
// no w/W/r/R/e commands and no w or e flags on s///.
func sedSafe(s string) bool {
	i := 0
	skipAddr := func() {
		for i < len(s) {
			switch c := s[i]; {
			case c >= '0' && c <= '9', c == '$', c == ',', c == '~', c == '!', c == ' ', c == '+':
				i++
			case c == '/' || c == '\\':
				d := byte('/')
				if c == '\\' && i+1 < len(s) {
					i++
					d = s[i]
				}
				i++
				for i < len(s) && s[i] != d {
					if s[i] == '\\' {
						i++
					}
					i++
				}
				i++
			default:
				return
			}
		}
	}
	for i < len(s) {
		for i < len(s) && strings.IndexByte(" \t\n;", s[i]) >= 0 {
			i++
		}
		if i >= len(s) {
			break
		}
		skipAddr()
		if i >= len(s) {
			return false
		}
		c := s[i]
		i++
		switch c {
		case 's', 'y':
			if i >= len(s) {
				return false
			}
			d := s[i]
			i++
			for n := 0; n < 2; n++ {
				for i < len(s) && s[i] != d {
					if s[i] == '\\' {
						i++
					}
					i++
				}
				i++
			}
			for i < len(s) && strings.IndexByte(";\n}", s[i]) < 0 {
				if c == 's' && (s[i] == 'w' || s[i] == 'e' || s[i] == 'W') {
					return false
				}
				i++
			}
		case 'p', 'P', 'd', 'D', 'n', 'N', 'g', 'G', 'h', 'H', 'x', 'l', '=', 'z', '{', '}', 'q', 'Q', 'F':
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++ // q/Q exit code
			}
		case 'a', 'i', 'c', '#', ':', 'b', 't', 'T':
			for i < len(s) && s[i] != '\n' && !(c != 'a' && c != 'i' && c != 'c' && c != '#' && s[i] == ';') {
				i++
			}
		default:
			return false // e, r, R, w, W, v and anything unknown
		}
	}
	return true
}

// awkSafe reports whether an awk program has no way to run commands or write files.
func awkSafe(p string) bool {
	if strings.Contains(p, "system") || strings.Contains(p, "getline") || strings.Contains(p, "|") || strings.Contains(p, "close(") || strings.Contains(p, "fflush") {
		return false
	}
	for i := strings.Index(p, "print"); i >= 0; {
		end := strings.IndexAny(p[i:], ";}\n")
		if end < 0 {
			end = len(p) - i
		}
		if strings.Contains(p[i:i+end], ">") {
			return false
		}
		next := strings.Index(p[i+5:], "print")
		if next < 0 {
			break
		}
		i += 5 + next
	}
	return true
}
