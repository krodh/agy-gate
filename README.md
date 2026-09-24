# agy-gate

`agy-gate` is a small, deterministic permission daemon for autonomous agents (specifically `agy`). It intercepts tool execution requests, instantly allowing safe commands and blocking dangerous ones using a deterministic policy engine. Anything ambiguous is sent to a secondary LLM judge for evaluation. It fails closed and tracks denial limits to stop runaway agents. It does deliberately not evaluate output or parse arbitrary payloads, nor does it require global mutable config state.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for design details.

## Installation

```bash
make install
```
This builds both the daemon (`agy-gate`) and the hook client (`agy-gate-hook`) into `~/.local/bin` and installs a systemd user unit from `contrib/agy-gate.service`.

## Usage

Use with `agy-run`:
```bash
agy-run --auto
```

Start the daemon (automatically done by the systemd unit):
```bash
agy-gate serve
```

Flags:
- `-socket`: socket path (default `$XDG_RUNTIME_DIR/agy-gate/gate.sock`)
- `-model`: judge model (default `gemini-3.6-flash-low`)
- `-workers`: number of judge workers (default 2)
- `-recycle`: restart worker after N requests (default 15)
- `-timeout`: daemon timeout (default 40s)
- `-isolate`: run judge in bwrap (default true)
- `-audit`: audit log path (default `~/.local/state/agy-gate/audit.jsonl`)
- `-dry-run`: audit decisions but do not enforce

## Eval

You can evaluate the policy and judge against known cases:
```bash
agy-gate eval testdata/eval/synthetic.jsonl
agy-gate eval testdata/eval/real.jsonl
```

## Known Limits

Code that build and test commands run is not inspected. The `agy-run` sandbox is the boundary there.
