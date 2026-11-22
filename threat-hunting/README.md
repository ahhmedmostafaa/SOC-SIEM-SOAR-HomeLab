# Threat Hunting

Automated alerts only fire on patterns someone already thought to write a detection for. Threat hunting is the complement to that: proactively searching for activity that *wouldn't* trigger a scheduled alert, based on a hypothesis rather than a pre-built rule.

Four hunts were conducted against this lab's live telemetry. Two surfaced real findings; two returned clean results — and a clean result, properly documented, is still a valid and useful outcome of a hunt. One hunt also surfaced an unrelated, genuine data-integrity issue, which was investigated on its own merits rather than dismissed.

## Hunt Summary

| # | Hunt | Hypothesis | Result |
|---|---|---|---|
| 1 | [PowerShell Encoded Command](./01-powershell-encoded-command.md) | An attacker is using Base64-encoded PowerShell to hide command content from plain-text log review | ✅ **Positive finding** — one matching event located |
| 2 | [Living Off the Land Binaries (LOLBins)](./02-living-off-the-land-binaries.md) | Native Windows tools (`certutil`, `bitsadmin`, `mshta`) are being abused to download or execute payloads | ⬜ **Negative finding** — no matching activity, documented as a clean baseline |
| 3 | [Off-Hours Logon Activity](./03-off-hours-logon-activity.md) | A compromised account is logging on outside normal working hours | ⬜ **Negative finding**, but only after correcting for a false-positive source (machine accounts) |
| 4 | [Lateral Movement Indicators (WMI/PsExec)](./04-lateral-movement-indicators.md) | An attacker is pivoting between hosts using WMI or PsExec-style remote execution | ⬜ **Negative finding** — and an unrelated data-integrity issue discovered and triaged along the way |

## Why Document Negative Findings At All

A hunting report that only records "found something" teaches nothing about what was actually searched or ruled out. Each negative-finding hunt below documents the exact query run, the time range covered, and — critically — *why the absence of results is meaningful* rather than just an empty search. This is also what separates a hunt from a detection: a detection runs forever on a schedule; a hunt is a point-in-time investigation whose conclusion ("no evidence of X as of this date") has to be stated as such, not silently discarded because nothing was found.
