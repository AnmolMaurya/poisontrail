# Arsenal demo runbook

Two ways to see PoisonTrail work. Reviewers with no Mac/model should use **replay**.

## A. Deterministic replay (no model, no ES, no admin)

```
python3 correlate/correlate.py
```

Reads `fixtures/agent-events.jsonl` (agent provenance) and
`fixtures/endpoint-events.jsonl` (distilled from real `eslogger` output) and
prints the incident report in `fixtures/expected-report.txt`, including the
full attribution chain and the `launchd`-reparented, Apple-signed OS evidence.

## B. Live, end to end (throwaway macOS VM)

Requirements: Apple Silicon macOS VM, [Ollama](https://ollama.com) running with a
local model (`ollama pull qwen2.5-coder:7b`), `python3`, and Full Disk Access on
the terminal for ES capture.

```
# terminal 1 — endpoint capture (sudo + Full Disk Access)
bash collectors/capture-es.sh

# terminal 2 — drive both sessions + correlate
bash demo/run-demo.sh

# clean up any LaunchAgent created during an allowed run
bash demo/teardown.sh
```

`run-demo.sh` performs the full scenario: Session 1 poisons memory, the poison is
removed from the repo, Session 2 recalls it and attempts the LaunchAgent
(denied at the tool boundary), then correlation produces the incident timeline.

### Optional: capture the allowed-replay OS evidence

The tool boundary denies the action, so no OS artifacts are produced. To capture
the endpoint evidence, replay the exact commands once, under `eslogger`, with the
inert payload — then tear down. See the commented block at the end of this file.

Safety: the payload only writes a timestamped marker file. No network, no
credentials, no protected-resource access, no detection evasion.
