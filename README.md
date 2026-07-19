# PoisonTrail

**Tracing cross-session AI-agent actions on macOS.**

PoisonTrail is an open-source, vendor-neutral defensive research tool that ties a
macOS OS-level action taken by an AI coding assistant back to the **untrusted
input** and the **earlier session** that caused it.

AI coding assistants read untrusted repositories, keep **persistent memory across
sessions**, and run local tools under your account. That combination enables a new
delivery path: untrusted repository content — a comment, a README, an issue — is
distilled into the assistant's persistent memory in one session, and **recalled in
a later, unrelated session** to drive a local OS action such as installing a
`LaunchAgent`. Because the persistence operation uses legitimate system utilities
and the resulting workload is started by `launchd`, code signing and direct process
ancestry alone cannot attribute the action to the earlier agent input.

PoisonTrail records provenance at the agent's tool boundary
(`source -> memory record -> recall -> tool request -> decision`) and correlates it
with macOS Endpoint Security telemetry (via `eslogger`) by **path, LaunchAgent
label, and timestamp** to reconstruct the full attribution chain — even across the
session boundary.

## Quick start (deterministic replay — no Mac/model/admin needed)

```
python3 correlate/correlate.py
```

Produces an incident report from captured fixtures (real telemetry from a validated
run), including the `launchd`-reparented, Apple-signed OS evidence:

```
INCIDENT: PT-0001
Decision: DENY
Risk: Persistence requested from cross-session untrusted memory

Original source:      README.md  (untrusted, session s1-onboarding)
Persistent memory:    dev-server-setup  (recalled in session s2-fix-devserver)
Requested action:     ~/Library/LaunchAgents/com.acme.devhelper.plist  [deny]
Endpoint evidence:    launchctl bootstrap ... ; /bin/bash devhelper.sh ppid=1 (launchd) ...

Attribution chain:
  README.md (untrusted)
    -> memory 'dev-server-setup' written in session s1-onboarding
    -> recalled in session s2-fix-devserver
    -> shell request for com.acme.devhelper  [DENY]
    -> OS: workload started by launchd (parent pid 1); Apple-signed system utilities
```

## Live demo (throwaway macOS VM)

See [`docs/arsenal-demo.md`](docs/arsenal-demo.md). In short: run `ollama`, start
`collectors/capture-es.sh`, then `bash demo/run-demo.sh`.

## What's in here

```
agent/poisontrail_agent.py   instrumented local agent (memory bank + provenance events)
collectors/capture-es.sh     macOS Endpoint Security capture via eslogger
correlate/correlate.py       correlation engine -> incident timeline (text or --json)
policies/launchagents.json   persistence-sensitive policy
demo/                        poisoned repo + run/teardown scripts
fixtures/                    captured events + expected report (deterministic replay)
docs/                        threat model + Arsenal runbook
```

## Design notes

- **Assistant-agnostic:** the bundled agent is a minimal transparent harness, but
  the provenance + correlation layer works against any tool-calling agent that can
  emit tool-boundary events (e.g. via a PreToolUse hook). The harness exists so the
  demo runs fully offline with no cloud account.
- **Behavior, not reasoning:** PoisonTrail records observable data flow — what was
  read, retained, recalled, and requested. It does not collect chain-of-thought or
  judge whether arbitrary text is "malicious."
- **Honest scope:** the recall-to-action step is the most model-dependent link and
  is reported as measured behavior; the correlation is deterministic. See
  [`docs/threat-model.md`](docs/threat-model.md).

## Related work & contribution

Memory poisoning of LLM agents is an active, well-published area — e.g. MemoryGraft
(poisoned experience retrieval from README-like content), MINJA (query-only memory
injection), Unit 42's work on indirect prompt injection into long-term memory, and
the "rules file backdoor" class in coding assistants. Agent tracing/provenance
(PROV-AGENT, OpenTelemetry GenAI) and macOS Endpoint Security tooling (eslogger,
Santa, BlockBlock) are likewise established.

PoisonTrail does **not** claim that memory poisoning, indirect prompt injection,
LaunchAgent persistence, provenance tracing, or Endpoint Security collection is
individually new. Its contribution is the **end-to-end provenance + correlation
layer**: preserving the relationship between untrusted repository content and a
persistent memory record, observing that record's recall in a later session, and
connecting the resulting tool request to macOS endpoint artifacts by path, label,
and timestamp.

## Status

Validated end to end in a throwaway macOS VM (Apple Silicon). Replay mode is
deterministic and self-contained. Roadmap: adapters for real assistants
(Claude Code hooks, Cline/Roo memory banks), richer policy packs, JSON incident
export for SIEMs.

## Safety

Run live mode in a throwaway VM only. The demo payload writes a harmless marker
file — no network, credentials, protected-resource access, or evasion. MIT licensed.

*Author: Anmol Maurya (Manifold Security). Vendor-neutral; not a commercial product.*
