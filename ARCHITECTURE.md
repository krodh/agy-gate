# agy-gate architecture

agy-gate auto-approves or blocks the tool calls of an unattended `agy` agent. It is a
PreToolUse hook backed by a small daemon: cheap deterministic rules decide the obvious calls in
microseconds, and a model decides the rest through warm `agy` worker processes.

Design goals, in order: never let a dangerous call through by accident (fail closed), stay out of
the way of normal work, stay small enough to read in one sitting.

## Moving parts

```
agy (always-proceed, set per run by agy-run --auto)
 │ PreToolUse "*"  ──►  agy-gate-hook            tiny static client, no JSON parsing
 │ PostInvocation  ──►  agy-gate-hook -post        │ unix socket, one request per connection
 │                                                 ▼
 │                                        agy-gate serve  (systemd --user)
 │                                          1. decode   payload -> Call
 │                                          2. policy   deny | allow | judge   (pure, no I/O but lstat)
 │                                          3. cache    judged calls only
 │                                          4. judge    agy worker pool -> {"decision","reason"}
 │                                          5. limits   3 consecutive / 20 total denials -> terminate
 │                                          6. audit    one JSONL line per decision
```

| Path | What | Budget |
|---|---|---|
| `cmd/agy-gate-hook` | hook client: stdin -> socket -> stdout | < 100 lines, imports only `os`, `net`, `io`, `time` |
| `cmd/agy-gate` | `serve`, `eval`, `version` | small dispatch |
| `internal/policy` | shell AST walk, path resolution, rule tables, `Decide` | the core; heavily tested |
| `internal/judge` | prompt, transcript reader, agy worker pool | |
| `internal/server` | socket loop, pipeline, cache, denial counters, audit | |

Total non-test Go should stay around 1,500 lines. Dependencies: the standard library and
`mvdan.cc/sh/v3/syntax` (a real bash parser; never its interpreter).

## Wire protocol (hook <-> daemon)

The client does not parse JSON. It sends one header line and the raw hook payload, half-closes, and
copies the daemon's reply to stdout:

```
agy-gate/1\t<event>\t<run-id>\t<workspace-list>\n     tab-separated; event: pre | post; "-" = empty
<raw agy hook payload>
```

The run id and workspace list come from `AGY_GATE_RUN` and `AGY_GATE_WORKSPACE` (colon-separated),
set by agy-run outside the agent's reach. The reply is the exact JSON agy expects. If the socket is
missing, the deadline (`AGY_GATE_TIMEOUT`, default 55 s) passes, or the reply is empty, the client
prints a fixed deny (for `post`: `{}`) and exits 0. With `AGY_GATE_ROLE=classifier` it denies
without connecting, so a classifier worker can never run tools.

## Policy (deterministic layer)

`Decide(Call) -> Verdict{Deny|Allow|Judge, Reason}`. The first match wins: deny rules, then
allow rules, and anything not provably safe goes to the judge. A call is allowed here only when
every part of it is understood.

Shell commands are parsed into an AST and walked. Every simple command is collected, including those
inside pipelines, lists, subshells, `$(..)`, `<(..)` and wrapper commands (`bash -c`, `sh -c`,
`env`, `nohup`, `timeout`, `nice`, `xargs`, `find -exec`, `command`, `exec`, `setsid`, `stdbuf`),
which are unwrapped and judged as their inner command. The walk tracks the working directory
through `cd`; once it becomes unknown, no relative path is safe. A word containing an unresolved
expansion is never a safe path (`~`, `$HOME` and `${HOME}` resolve to the real home). Every path
argument and redirect target is resolved: `Clean`, then symlinks via the deepest existing ancestor,
and then classified as `workspace | scratch (/tmp) | protected | outside`.

Deny (hard, no model):
- protected paths, read or write: credentials (`~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`,
  `~/.git-credentials`, `~/.gnupg`, `~/.kube`, `~/.docker/config.json`, `/etc/shadow`, key files) and
  the gate itself plus everything the agent could use to disable it (`~/.gemini/**`,
  `~/.config/agy-profiles`, `~/.local/bin`, the gate's state and socket dirs);
- writes to persistence and system locations (shell rc files, crontab, systemd units, `.git/hooks`,
  `/etc`, `/usr`, `/boot`, `/var` except `/var/tmp`);
- privilege (`sudo`, `su`, `doas`, `pkexec`, setuid chmod), destructive disk tools, recursive
  delete outside the workspace or of the workspace root;
- remote code execution (download or decode piped into an interpreter, `bash <(..)`), `/dev/tcp`,
  cloud metadata addresses;
- obfuscation: `eval`, a command name that is not a literal, env hijacks (`LD_PRELOAD`,
  `LD_LIBRARY_PATH`, `BASH_ENV`, `PATH`), `git config` of `core.sshCommand` / `core.hooksPath` /
  `core.fsmonitor` / `core.pager` / `alias.*` / `credential.*` / `*.command`;
- irreversible remote git ops: force push, `--mirror`, delete refs, `filter-branch` / `filter-repo`;
- publish and deploy (`npm publish`, `docker push`, `kubectl` mutations, `terraform apply`, ...);
- nested agents with permission-bypass flags; exfiltration-shaped network commands (upload flags,
  `@file`, computed arguments).

Allow (no model): read-only commands, git read subcommands, build and test commands
(`go`, `cargo`, `npm test`, `make`, `pytest`, ...), and file creation or edits whose every path is
in the workspace or scratch; non-shell reads and writes inside the workspace; `ask_question`.

Everything else goes to the judge: network fetches, anything outside the workspace that is not
protected, unknown tools, MCP and subagent calls, and shell the parser cannot fully resolve.

Known limit: code that build and test commands run is not inspected. The agy-run sandbox is the
boundary there, as it is in Claude Code's auto mode.

## Judge (model layer)

Workers are long-lived `agy` processes speaking stream-json, each running a no-tools agent whose
system prompt is `internal/judge/prompt.md`:

```
agy --agent agy-gate-judge --add-dir <ABS workerdir> --model <m> --input-format stream-json --output-format stream-json -p=
  stdin : {"event":"user","message":{"content":"<request>"}}
  stdout: ... {"event":"result","result":{"status":"SUCCESS","response":"{\"decision\":...}","usage":{...}}}
```

- A worker is warmed with a throwaway request (agy starts lazily, ~8-12 s) and recycled after 6
  requests (its context grows ~2.3k tokens per request). The replacement is spawned first.
- Workers run under bwrap with a hidden home, `AGY_GATE_ROLE=classifier` and an empty allow list.
  `--add-dir` must be absolute or agy ignores the agent's frontmatter.
- A request carries only the user's own messages (transcript entries with `type: USER_INPUT` and
  `source: USER_EXPLICIT`, text inside `<USER_REQUEST>`), the pending call, and the policy's note
  on why it did not decide. Never tool output or the agent's own text: that is where prompt
  injection comes from.
- The transcript is writable inside the sandbox, so the first user requests seen for a conversation
  are pinned in memory; a transcript whose seen prefix changes is treated as tampered.
- Output must be one JSON object. Anything else, a timeout, or a dead worker is retried once on
  another worker, then denied. A quota error disables the judge for 5 minutes (fast deny).
- Default model `gemini-3.6-flash-low`, the one flash tier that reasons before answering; it uses
  the Gemini quota pool. Measured 10-15 s median per request with the full prompt.

## Denials

Every deny reason is written as an instruction to the agent, because agy shows it verbatim:
`[agy-gate/<layer>] <why>. Do not retry or work around this; use a safer approach or stop and
report what you need.` After 3 consecutive or 20 total denials in a conversation, the reason is
prefixed `ESCALATED:` and the PostInvocation hook terminates the run (agy-run jobs are headless;
there is no one to ask). These numbers are the ones Claude Code's auto mode uses.

## Efficiency

- Deterministic decisions never leave the daemon process and do no I/O besides `lstat` on
  candidate paths. Rule tables are `switch` statements and maps built at init; no regular
  expressions on the hot path.
- The payload is decoded once into one flat struct holding every known arg key; no
  `map[string]any`.
- The hook client is a separate static binary (`CGO_ENABLED=0 -trimpath -ldflags="-s -w"`) that
  does not import `encoding/json` or `fmt`, so exec-to-exit is dominated by the kernel, not the
  Go runtime.
- Cache: judged verdicts keyed by sha256(conversation, tool, canonical args, cwd, workspace,
  content hash of an executed workspace script); a plain map dropped when it reaches 4096 entries.
- Audit: one `write(2)` per decision on an `O_APPEND` file.

## Integration: `agy-run --auto`

agy-run writes `toolPermission: always-proceed` into the per-run settings, mounts a generated
`hooks.json` read-only over `~/.gemini/config/hooks.json`, mounts the hook binary read-only and the
socket directory, sets `AGY_GATE_*`, and adds `--add-dir` for each work dir (headless agy has no
workspace otherwise). Global settings stay on request-review, so a broken gate can never open up
interactive sessions.

## Threat model

The agent is untrusted: it may be confused, or steered by content it read. It
runs as the same Unix user as the gate, inside agy-run's bwrap sandbox. The gate
must hold even if the agent tries to switch it off, so everything that could
disable or bypass it is out of the agent's reach:

| bypass | defence |
|---|---|
| replace the socket with an allow-all listener | socket directory mounted read-only in the sandbox (connect works on a read-only mount, unlink and bind do not; verified); the hook never falls back to `/tmp`, which the agent owns |
| edit or remove the hook | per-run `hooks.json` and the hook binary mounted read-only; `--auto` refuses `--open` |
| register hooks, MCP servers or agents agy would run outside the gate | `~/.gemini/config` read-only; the work dir's `.agents`, `.agent`, `_agents`, `_agent` read-only; writes to them are also denied by policy |
| forge user approval in the transcript | the transcript is protected from writes by policy; the daemon pins the user requests it has seen per conversation |
| make a judge worker run tools | workers have no tools, an empty allow list, a hidden home, and `AGY_GATE_ROLE=classifier`, which makes the hook deny without asking |
| talk the judge into it | the judge sees only the user's messages, the call and the policy's note, never tool output or the agent's text |

Out of scope: what programs do after an allowed build or test step starts them,
and anything the sandbox itself permits.

## Verified agy facts this depends on (agy 1.2.8)

- Hooks can only enforce under `always-proceed`; there, `ask` and `force_ask` are ignored, so the
  gate answers only allow or deny.
- A hook that crashes, prints non-JSON or times out aborts the call (fail closed). A missing hook
  lets everything run, which is why the hooks file is mounted read-only per run.
- The deny reason reaches the model verbatim. Profile deny rules still apply under always-proceed.
- agy splits a Markdown agent file at H1 headings and uses only the first section as the system
  prompt, so the judge prompt's headings are demoted one level when the agent file is written.
- A PostInvocation payload has no `toolCall`; the daemon answers it from the denial counters only.
- Warm judge latency on the agy backend: median 10-15 s, tail ~45 s; context grows ~2.3k tokens
  per request, hence recycling after 6 requests.
