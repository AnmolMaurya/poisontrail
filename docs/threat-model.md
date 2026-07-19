# Threat model

## The shift

AI coding assistants now combine three capabilities that used to be separate:

1. They ingest **untrusted content** — repositories, docs, issues, comments.
2. They keep **persistent memory** across sessions (memory banks, saved notes,
   project conventions).
3. They can **execute commands and modify local files** under your account.

## The attack

Untrusted repository content is crafted to read like a durable "project
convention." In one session the assistant distills it into persistent memory.
The content is then removed from the repository. In a **later, unrelated
session**, the assistant recalls the stored memory and is driven to take a
local OS action — here, installing a user `LaunchAgent` for persistence.

There is no exploit and no malware in the traditional sense: a trusted developer
tool, running as the user, uses Apple-signed system utilities to do something the
user never asked for in that session.

## Why macOS detection struggles

Captured from a real run (see `fixtures/`):

- The persistence payload is **reparented to `launchd` (pid 1)** — process
  ancestry no longer points back to the assistant.
- Every binary in the chain (`launchctl`, `bash`, `touch`) is an **Apple-signed
  platform binary** — code-signing / Team ID checks add nothing.
- Endpoint telemetry can see *that* a plist was written and a process ran, but
  not *which document, memory record, or earlier session* caused it.

## What PoisonTrail adds

PoisonTrail preserves the missing provenance at the agent boundary
(`source -> memory record -> recall -> tool request -> decision`) and correlates
it with Endpoint Security telemetry by **path, LaunchAgent label, and timestamps**
— not process ancestry — to attribute the OS action across the session boundary.

## Scope and honesty

- The recall-to-action step is the most **model-dependent** link; a weaker local
  model reliably recalls but does not always act autonomously. Reported as
  measured behavior, not a guaranteed one-shot.
- PoisonTrail uses explicit **behavioral / provenance** policies. It does **not**
  attempt to judge whether arbitrary text is semantically malicious, and does not
  collect private model reasoning / chain-of-thought.
- MITRE ATT&CK: T1543.001 (Launch Agent), T1546 (Event Triggered Execution).
