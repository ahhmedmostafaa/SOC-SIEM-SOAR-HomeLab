# Detection Engineering

Ten custom SPL detections, each validated against a real attack executed in this lab — not theoretical queries written against sample data.

## A Standardized Alert Schema

Every detection in this folder outputs the **same core field set**, regardless of what it detects:

```
alert_name | alert_type | mitre_technique | severity | host | target_identity | source_ip | ... | first_seen | last_seen | recommended_actions
```

This is a deliberate design choice, not a coincidence. Splunk's alert action sends this table as JSON to a single Shuffle webhook, and the `SOC-Master-Playbook` workflow uses `alert_type` to route the event to the correct enrichment sub-workflow (IP reputation lookup, identity context, pfSense block, etc.) — see [`soar-automation/`](../soar-automation). Writing detections "SOAR-ready" from the start avoided having to retrofit ten different, incompatible alert formats later.

`recommended_actions` is also pre-formatted as a semicolon-delimited string (`;;` separator) specifically so the email/Telegram notification workflow can split it into a readable numbered checklist for the analyst — the detection does the enrichment work, the automation just renders it.

## Shared Alert Configuration Pattern

Beyond the field schema, every alert in this folder is configured identically at the Splunk alert-action level, with only two settings varying per detection:

| Setting | Value |
|---|---|
| Schedule | Cron `*/5 * * * *` (every 5 minutes) — except Port Scan, which uses a 15-minute search window to give slow/stealth scans enough lookback to cross threshold |
| Trigger condition | Number of results > 0, fired **Once** per run (not per result) |
| Throttle | Enabled on all ten |
| Trigger Actions | Add to Triggered Alerts + **Webhook** → Shuffle `SOC-Master-Playbook` |

**What varies per detection: the suppression field.** Each alert suppresses repeat notifications for 30 minutes (10 minutes for Port Scan) based on whichever field uniquely identifies "the same ongoing incident" for that specific attack type — otherwise every alert would re-fire and re-trigger the SOAR webhook every 5 minutes for as long as the underlying activity continues, flooding the analyst and the automation layer with duplicate incidents instead of one.

| Detection | Suppress on field |
|---|---|
| Brute Force (4625) | `Source_Network_Address` |
| Kerberoasting (4769) | `target_identity` (the account being targeted) |
| Port Scan (pfSense) | `source_ip` |
| RDP Logon (4624) | `source_ip` |
| SSH Brute Force (Linux) | `source_ip` |
| Privileged Group Change | `added_account` |
| Log Clearing | `host` |
| Registry Persistence | `Computer` |
| Credential Dumping — LSASS | `Computer` |
| Suspicious Scheduled Task | `host` |

This distinction matters: suppressing a brute-force alert by *source IP* makes sense because the attacking host is the constant across repeat attempts, while suppressing a Kerberoasting alert by *target identity* makes sense because the account being roasted is the constant, even if the technique is used again later from a different source.

## Detection Index

| # | Detection | MITRE Technique | Data Source | Severity Logic |
|---|---|---|---|---|
| 1 | [Brute Force – Multiple Failed Logons](./01-brute-force-windows.md) | T1110.001 | Windows Security (4625) | ≥20 Critical / ≥10 High / else Medium |
| 2 | [Kerberoasting Detected](./02-kerberoasting.md) | T1558.003 | Windows Security (4769) | ≥10 SPNs Critical / ≥5 High / else Medium |
| 3 | [Port Scan Detected (pfSense)](./03-port-scan-pfsense.md) | T1046 | pfSense filterlog | ≥100 ports Critical / ≥50 High / else Medium |
| 4 | [RDP Logon Detected](./04-rdp-logon.md) | T1021.001 | Windows Security (4624, Type 10) | Multi-source IP or high volume → Critical/High |
| 5 | [SSH Brute Force Detected (Linux)](./05-ssh-brute-force-linux.md) | T1110.001 | Azure VM auth.log (via HEC) | ≥20 Critical / ≥10 High / else Medium |
| 6 | [Privileged Group Membership Change](./06-privileged-group-change.md) | T1098 | Windows Security (4728/4732/4756) | Domain/Enterprise Admins → Critical, else High |
| 7 | [Log Clearing Detected](./07-log-clearing.md) | T1070.001 | Windows Security/System (1102/104) | Always Critical |
| 8 | [Registry Persistence – Run Key Modified](./08-registry-persistence.md) | T1547.001 | Sysmon (Event ID 13) | Suspicious interpreter in path → High |
| 9 | [Credential Dumping – LSASS Access](./09-credential-dumping-lsass.md) | T1003.001 | Sysmon (Event ID 10) | Always High |
| 10 | [Suspicious Scheduled Task Created](./10-scheduled-task.md) | T1053.005 | Windows Security (4698) | Suspicious interpreter in command → High |

## Why These Ten

The selection wasn't arbitrary — it was built to cover the actual stages of an intrusion, not just repeat the same technique ten times:

- **Initial Access / Credential Access:** brute force (Windows + Linux), Kerberoasting, LSASS dumping
- **Discovery:** network port scanning
- **Persistence:** scheduled tasks, registry run keys
- **Privilege Escalation:** privileged group membership changes
- **Lateral Movement:** RDP logons
- **Defense Evasion:** event log clearing

Each detection also deliberately filters out the noise that would otherwise drown it in false positives — machine accounts (`$`), localhost, known Microsoft/OEM processes, and default Windows scheduled tasks are excluded wherever relevant (see individual files for the exact exclusion logic).
