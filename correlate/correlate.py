#!/usr/bin/env python3
"""PoisonTrail correlation engine.

Joins agent-side provenance events with macOS Endpoint Security telemetry to
attribute a persistence-sensitive OS action back to the untrusted input and the
prior session that caused it.

Runs in two modes:
  * replay (default): reads captured fixtures for deterministic evaluation
  * live: point --agent / --endpoint at real logs

  python3 correlate/correlate.py                 # replay fixtures
  python3 correlate/correlate.py --json          # machine-readable
  python3 correlate/correlate.py --agent ~/poc/logs/agent.jsonl \
                                 --endpoint ~/poc/logs/es.jsonl
"""
import argparse, json, os, re

def load_jsonl(path):
    rows = []
    if not path or not os.path.exists(path):
        return rows
    with open(path) as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except json.JSONDecodeError:
                pass
    return rows

SENS = ("launchagents", "launchctl", "launchd", ".plist")
def is_sensitive(s):
    s = (s or "").lower()
    return any(k in s for k in SENS)

def plist_path(cmd):
    m = re.search(r'([~/][^\s"\']*LaunchAgents/[^\s"\']+\.plist)', cmd or "")
    return m.group(1) if m else None

def label_from_path(p):
    return os.path.basename(p)[:-6] if p and p.endswith(".plist") else None

# --- Endpoint Security field accessors (tolerant of raw eslogger + fixtures) ---
def es_path(e):
    try: return e["event"]["create"]["destination"]["existing_file"]["path"]
    except Exception: return None
def es_args(e):
    try: return e["event"]["exec"]["args"]
    except Exception: return None
def es_signing(e):
    return (e.get("process") or {}).get("signing_id")
def es_platform(e):
    return (e.get("process") or {}).get("is_platform_binary")
def es_parent_pid(e):
    try: return e["process"]["parent_audit_token"]["pid"]
    except Exception: return None

def build(agent, endpoint):
    sources, records, recalls, requests = {}, {}, [], []
    for a in agent:
        ev = a.get("event")
        if ev == "read":
            sources[a.get("source")] = a
        elif ev == "memory_write":
            records[a.get("record_id")] = a
        elif ev == "recall":
            recalls.append(a)
        elif ev == "tool_request":
            requests.append(a)

    incidents = []
    for r in requests:
        cmd = r.get("cmd", "")
        if not (is_sensitive(cmd) or is_sensitive(json.dumps(r.get("args", "")))):
            continue
        pp = plist_path(cmd)
        label = label_from_path(pp)
        stem = label.split(".")[-1] if label else None
        rec = records.get(r.get("record_ref"))
        src = sources.get(rec.get("source")) if rec else None
        recalled_in = next((rc.get("session") for rc in recalls
                            if r.get("record_ref") in rc.get("records", [])), None)

        evidence = []
        for e in endpoint:
            p = es_path(e); args = es_args(e)
            hay = " ".join([p or ""] + (args or []))
            if ((label and label in hay) or (stem and stem in hay) or
                (pp and pp in hay) or ("LaunchAgents" in hay) or
                (args and args[0].endswith("launchctl"))):
                evidence.append(e)

        incidents.append(dict(request=r, plist=pp, label=label, record=rec,
                              source=src, recalled_in=recalled_in, evidence=evidence))
    return incidents

def render(incidents):
    if not incidents:
        print("No persistence-sensitive cross-session incidents found.")
        return
    for i, inc in enumerate(incidents, 1):
        r = inc["request"]; rec = inc["record"] or {}; src = inc["source"] or {}
        decision = (r.get("decision") or "unknown").upper()
        print("=" * 66)
        print(f"INCIDENT: PT-{i:04d}")
        print(f"Decision: {decision}")
        print("Risk: Persistence requested from cross-session untrusted memory\n")
        print("Original source:")
        print(f"  path:                {src.get('source') or rec.get('source') or 'unknown'}")
        print(f"  sha256:              {src.get('sha256', '-')}")
        print(f"  trust:               {src.get('trust', 'untrusted')}")
        print(f"  ingested in session: {rec.get('session', '-')}\n")
        print("Persistent memory:")
        print(f"  record:              {rec.get('record_id', '-')}")
        print(f"  recalled in session: {inc.get('recalled_in', '-')}\n")
        print("Requested action:")
        print(f"  tool:                {r.get('tool', '-')}")
        print(f"  plist:               {inc.get('plist', '-')}")
        print(f"  label:               {inc.get('label', '-')}")
        print(f"  policy result:       {r.get('decision', '-')}\n")
        ev = inc["evidence"]
        print("Endpoint evidence:")
        if not ev:
            print("  none — action blocked before reaching the OS")
        else:
            if decision == "DENY":
                print("  (from controlled allowed replay — see docs/arsenal-demo.md)")
            for e in ev:
                if es_args(e):
                    print(f"  exec   {' '.join(es_args(e))[:80]}")
                    print(f"         [signing_id={es_signing(e)} platform={es_platform(e)} ppid={es_parent_pid(e)}]")
                elif es_path(e):
                    print(f"  create {es_path(e)}")
                    print(f"         [by {es_signing(e)}]")
        print("\nAttribution chain:")
        print(f"  {src.get('source') or rec.get('source', 'source')} (untrusted)")
        print(f"    -> memory '{rec.get('record_id', '-')}' written in session {rec.get('session', '-')}")
        print(f"    -> recalled in session {inc.get('recalled_in', '-')}")
        print(f"    -> {r.get('tool', 'tool')} request for {inc.get('label', 'launchagent')}  [{decision}]")
        if ev:
            print("    -> OS: workload started by launchd (parent pid 1); Apple-signed system utilities")
    print("=" * 66)

def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description="PoisonTrail correlation engine")
    ap.add_argument("--agent", default=os.path.join(base, "fixtures", "agent-events.jsonl"))
    ap.add_argument("--endpoint", default=os.path.join(base, "fixtures", "endpoint-events.jsonl"))
    ap.add_argument("--json", action="store_true", help="emit JSON instead of the text report")
    args = ap.parse_args()
    incidents = build(load_jsonl(args.agent), load_jsonl(args.endpoint))
    if args.json:
        print(json.dumps(incidents, indent=2, default=str))
    else:
        render(incidents)

if __name__ == "__main__":
    main()
