# Contributing

Thanks for your interest in improving the MICCMAC Zero Trust Device Readiness Toolkit.

## Ways to contribute

- **Implement checks.** Each module in `miccmac/checks/` contains scaffolded
  checks marked `NOT_IMPLEMENTED`. Real detection logic for any platform
  (Windows, Linux, macOS, cloud) is welcome. See "Implementing a check" below.
- **Add platform collectors.** Helpers that gather device facts and pass them
  into the engine via the `context` dict. A connector lives in (or under)
  `miccmac/connectors/`; it runs *before* `engine.run_assessment` and feeds
  the engine a populated `context["facts"]`.
- **Improve control mappings.** See `data/control-mappings.yaml`.
- **Report issues.** Bugs, false results, and methodology questions are all useful.

## Where to start

If you're new and looking for a tractable first contribution, the README's
[Lowest-effort first concrete target](README.md#lowest-effort-first-concrete-target)
lists three starting paths — pick whichever environment you already have a
lab in (Linux + osquery, Windows + Sysmon + Defender, or macOS + Jamf /
Kandji). Implementing one property's worth of checks (typically 3 – 4) for
one platform is a complete, mergeable contribution.

## Development setup

```bash
git clone https://github.com/liliyke/miccmac-zt-readiness.git
cd miccmac-zt-readiness
python -m pip install -r requirements-dev.txt
python -m miccmac assess localhost
```

## Implementing a check

Every check is a single `CheckResult` returned by a property module's
`_run_checks(target, context)` function. To turn a stub into a real check:

1. Decide what platform(s) it covers. If your check only makes sense on one
   OS, branch on `context["facts"]["os"]` and return
   `Status.NOT_APPLICABLE` for everything else — `NOT_APPLICABLE` checks are
   excluded from scoring rather than failed.
2. Collect the evidence. Either consume facts that a connector has already
   gathered into `context["facts"]`, or perform a lightweight lookup inline
   if it doesn't need remote access (e.g. reading a local file).
3. Decide the outcome and set the four fields:
   - `status` — `PASS`, `PARTIAL`, `FAIL`, `NOT_APPLICABLE`, or `ERROR`
   - `detail` — short human-readable finding (one sentence)
   - `evidence` — command output, file path, API response id, etc.
   - `control_refs` — leave as already-defined unless you have a better one

### Example: implementing MON-03 for Linux

```python
# miccmac/checks/monitored.py
from miccmac.model import CheckResult, Status

def _run_checks(target, context):
    facts = context.get("facts", {})
    results = []

    # --- MON-03: EDR / endpoint telemetry agent installed and healthy ---
    if facts.get("os") == "linux":
        agents = facts.get("edr_agents", [])      # populated by a connector
        healthy = [a for a in agents if a.get("status") == "running"]
        if healthy:
            status = Status.PASS
            detail = f"{len(healthy)} EDR agent(s) running ({', '.join(a['name'] for a in healthy)})."
            evidence = "systemctl is-active falcon-sensor / sentinelone / wazuh-agent"
        elif agents:
            status = Status.PARTIAL
            detail = "EDR agent installed but not running."
            evidence = str(agents)
        else:
            status = Status.FAIL
            detail = "No EDR / telemetry agent detected."
            evidence = "no matching systemd units"
    else:
        status = Status.NOT_APPLICABLE
        detail = f"MON-03 Linux variant — facts.os was {facts.get('os')!r}."
        evidence = ""

    results.append(CheckResult(
        check_id="MON-03",
        name="EDR / endpoint telemetry agent installed and healthy",
        status=status,
        detail=detail,
        evidence=evidence,
        control_refs=['NIST 800-53 SI-4', 'CIS v8 13.7'],
    ))
    # ... other checks ...
    return results
```

Then make sure a connector populates `facts["edr_agents"]` upstream — e.g.
by running `systemctl list-units --type=service --no-pager` over SSH and
parsing for known agent names.

## Pull requests

1. Open an issue describing the change before large work.
2. Keep one logical change per pull request.
3. Each new check should set `status`, `detail`, `evidence`, and `control_refs`.
4. Each new check should also include at least one unit test in
   `tests/test_engine.py` (or a new `tests/test_<property>.py`) covering one
   PASS path and one FAIL path with mocked `context`.
5. Run `pytest` before submitting.

## Anatomy of a working check (what reviewers look for)

| Field | Good | Avoid |
|---|---|---|
| `status` | One of `PASS` / `PARTIAL` / `FAIL` / `NOT_APPLICABLE` / `ERROR` | Leaving as `NOT_IMPLEMENTED` |
| `detail` | One sentence stating the finding | Multi-paragraph explanations |
| `evidence` | Specific: command, file path, registry key, API response id | "Checked the system" |
| `control_refs` | The pre-populated values (NIST / CIS) | Empty list, or invented refs |
| Branching | Per-OS where applicable; `NOT_APPLICABLE` outside | Failing checks that don't apply |

## Conduct

This project follows the contributor expectations in `CODE_OF_CONDUCT.md`.
Be respectful and constructive.
