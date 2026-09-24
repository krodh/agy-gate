# agy-gate

Auto-approval for unattended [Antigravity CLI](https://antigravity.google) (`agy`) agents.

agy-gate decides every tool call an agent makes: it denies the clearly dangerous,
allows the clearly safe in microseconds, and asks a model about the rest. It lets
a headless `agy` job work without a hand-written allow list and without
`--dangerously-skip-permissions`.

**For** people who delegate bounded jobs to `agy` inside a sandbox (for example
with `agy-run`) and want those jobs to stop tripping over permission prompts
without handing the agent the whole machine.

**Not** a sandbox. It judges what the agent asks to do, not what the programs it
runs do afterwards (a test suite the agent wrote can still do anything the
sandbox allows). It does not inspect tool output, does not do interactive
approval, and does not publish, deploy or push on the agent's behalf: those stay
with a human or the orchestrating agent.

## How it works

```
agy (always-proceed) ── PreToolUse ──► agy-gate-hook ── unix socket ──► agy-gate serve
                                                                         1. policy: deny | allow | judge
                                                                         2. judge: warm agy workers (Gemini)
                                                                         3. denial limits, audit log
```

1. **Policy.** Shell commands are parsed with a real bash parser. Every command
   that would run is checked, including those inside pipelines, subshells,
   `$(...)`, and wrappers such as `bash -c`, `env`, `xargs` and `find -exec`.
   Paths are resolved the way the kernel resolves them and sorted into workspace,
   scratch, outside, system and secret zones. Reads, edits, builds and tests in
   the workspace are allowed; credential access, persistence, privilege
   escalation, remote code execution, history rewrites, publishing and deploying
   are denied. Anything not provably safe goes to the judge.
2. **Judge.** A no-tools `agy` agent running `gemini-3.6-flash-low` gets the
   user's own messages, the pending call and the policy's note. It never sees
   tool output or the agent's own text, which is where prompt injection comes in.
   It answers allow or deny with a reason.
3. **Limits.** After 3 denials in a row or 20 in total, the run is terminated.
   Every deny reason is written as an instruction to the agent, because agy shows
   it verbatim.
4. **Probe.** A fast PreInvocation hook scans the latest tool outputs for prompt
   injection attempts and adds an ephemeral warning if it sees any.

Everything fails closed: if the daemon is down, slow or confused, the call is
denied. Design and threat model: [ARCHITECTURE.md](ARCHITECTURE.md).

## Numbers (Raspberry Pi 5, agy 1.2.8)

| | |
|---|---|
| policy decision, shell command | 21 µs, 80 allocs |
| policy decision, file view | 3.6 µs, 5 allocs |
| hook exec-to-exit, deterministic answer | 0.5–2 ms |
| judge decision | 10–15 s median, up to ~45 s (agy backend) |
| real calls from past agy jobs decided without the judge | 151 of 175 (81% allowed, 5% denied) |

## Install

Requires Go 1.27, `bwrap`, and `agy` in `~/.local/bin`.

```bash
make install                         # binaries to ~/.local/bin, systemd user unit
systemctl --user enable --now agy-gate
```

`contrib/agy-run-auto.patch` adds `--auto` to `agy-run`: per-run always-proceed,
the hook and its binary mounted read-only, the socket directory and agy's
customization folders read-only inside the sandbox, and `--add-dir` for each
work dir. Global agy settings are never changed.

```bash
agy-run --auto --profile default --work ./job -- -p "..." --model gemini-3.6-flash-low
```

## Daemon flags

| flag | default | |
|---|---|---|
| `-socket` | `$XDG_RUNTIME_DIR/agy-gate/gate.sock` | never under `/tmp` |
| `-model` | `gemini-3.6-flash-low` | judge model; uses the Gemini quota pool |
| `-workers` | 2 | warm judge processes |
| `-recycle` | 6 | requests per worker; context grows ~2.3k tokens per request |
| `-timeout` | 40s | per judge request |
| `-isolate` | true | run judge workers under bwrap with a hidden home |
| `-audit` | `~/.local/state/agy-gate/audit.jsonl` | one line per decision, no file contents |
| `-dry-run` | false | answer allow, audit the real decision |

## Evaluate

```bash
make test lint                                       # unit tests, gofmt, vet
bin/agy-gate eval testdata/eval/synthetic.jsonl      # policy only
bin/agy-gate eval -judge testdata/eval/synthetic.jsonl   # with live judge workers
```

`synthetic.jsonl` holds 115 labelled cases. `make eval` also replays
`testdata/eval/local/real.jsonl` if present: real tool calls from your own agy
jobs, kept out of git because they contain local paths and repository names.

## Known limits

- Code run by allowed build and test commands (`go test`, `make`, `npm test`)
  is not inspected. The sandbox is the boundary there, as in Claude Code's auto
  mode.
- The policy cannot see intent: `rm -rf build/` is allowed whether or not the
  user asked for it. Scope-dependent calls it cannot decide go to the judge.
- The judge is only as fast as the agy backend. Most calls never reach it.
- Built and tested against agy 1.2.8. Hook and agent-file behaviour it relies on
  is listed in ARCHITECTURE.md; re-check it after an agy update.

## License

MIT
