# Detection 10 — Suspicious Scheduled Task Created

| | |
|---|---|
| **MITRE ATT&CK** | T1053.005 — Scheduled Task/Job |
| **Data Source** | Windows Security Log, Event ID 4698 |
| **Severity Logic** | Suspicious interpreter in the task command → High, else Medium |

## Attack Simulated

On `LAB-WS10`, a scheduled task was created to run as `SYSTEM` — the highest local privilege level — launching a hidden PowerShell command at a fixed future time:

```powershell
schtasks /create /tn "UpdateCheckTask" /tr "powershell.exe -WindowStyle Hidden -Command Write-Host Test" /sc once /st 23:59 /ru SYSTEM /f
```

Running the task as `SYSTEM` rather than the current user mirrors a real privilege-escalation-via-persistence pattern: an attacker with local administrative rights creating a SYSTEM-level task to ensure their payload survives logoff and runs with maximum privilege, not merely to persist across the current user's sessions.

## Rationale

Scheduled tasks are a common, low-effort persistence mechanism: create a task that re-executes a payload at logon, at an interval, or on next boot, and the attacker no longer needs an active session to maintain access. The detection challenge is almost entirely about noise — Windows itself and nearly every installed application create scheduled tasks constantly for completely legitimate reasons.

## Detection Logic

```spl
index=* EventCode=4698
| rex field=_raw "Task Name:\s+\\\\(?<task_name>\S+)"
| rex field=_raw "<Command>(?<task_command>.*?)</Command>"
| rex field=_raw "<Arguments>(?<task_arguments>.*?)</Arguments>"
| rex field=_raw "Account Name:\s+(?<Account_Name>\S+)"
| where NOT match(task_name, "^Microsoft\\\\Windows\\\\")
| where NOT match(Account_Name, "\$")
| where NOT match(task_command, "(?i)^C:\\\\Windows\\\\Explorer\.EXE$")
| where NOT match(task_command, "(?i)onedrive|teams\.exe|googleupdate|adobe|dropbox")
| eval mitre_technique="T1053.005 - Scheduled Task/Job"
| eval alert_name="Suspicious Scheduled Task Created (4698)"
| eval severity=case(match(task_command, "(?i)powershell|cmd\.exe|wscript|mshta|rundll32"), "High", true(), "Medium")
| convert ctime(_time) as event_time
| eval recommended_actions="A new scheduled task (" . task_name . ") was created on " . ComputerName . " by " . Account_Name . ".;;Review the task command (" . task_command . " " . task_arguments . ") for malicious intent.;;Verify with " . Account_Name . " whether they created this task intentionally.;;If unauthorized, delete the scheduled task and investigate " . ComputerName . " for further persistence mechanisms.;;Check for similar scheduled tasks created around the same time on other hosts."
| eval alert_type="scheduled_task", source_ip="N/A (host-level event)", target_identity=Account_Name, host=ComputerName
| table alert_name, alert_type, mitre_technique, severity, host, target_identity, source_ip, task_name, task_command, task_arguments, event_time, recommended_actions
```

### Why it's built this way

- **`NOT match(task_name, "^Microsoft\\Windows\\")`** removes the single largest source of noise: Windows itself creates dozens of built-in scheduled tasks under this namespace (diagnostics, telemetry, maintenance) that have nothing to do with user or attacker activity.
- **Machine account exclusion (`\$`)** removes tasks created by the SYSTEM/machine context as part of normal OS operation, as opposed to a human (or attacker-controlled) account explicitly creating one.
- **Named-application exclusions** (`onedrive`, `teams.exe`, `googleupdate`, `adobe`, `dropbox`) target the specific, high-volume legitimate software update tasks observed during lab testing that would otherwise appear repeatedly in the triggered-alerts list and dilute attention from genuinely new tasks.
- **Severity escalation on interpreter presence** mirrors the same logic used in the Registry Persistence detection — a scheduled task that directly launches `powershell.exe`, `cmd.exe`, `wscript`, `mshta`, or `rundll32` is a stronger persistence/execution signal than one launching a named, compiled application.

## Alert Configuration

| Setting | Value |
|---|---|
| Schedule | Cron `*/5 * * * *` (every 5 minutes) |
| Search window | Last 5 minutes |
| Expires | 24 hours |
| Trigger condition | Number of results > 0 |
| Trigger | **Once** per run |
| Throttle | ✅ Enabled |
| **Suppress results containing field value** | `host` |
| Suppress triggering for | 30 minutes |
| Trigger Actions | Add to Triggered Alerts (**Severity: High**) + **Webhook** → Shuffle `SOC-Master-Playbook` |

## Validation

This was the single most frequently triggered detection during lab testing (appearing repeatedly in `Triggered Alerts` across multiple days), which is expected and appropriate — scheduled task creation is both a common legitimate activity and a common attacker technique, and the exclusion list above was iteratively refined based on exactly which *legitimate* tasks were initially, incorrectly, flagged.

## SOAR Output: Incident Email

The incident email generated for this detection is shown in the Master Playbook write-up: [`soar-automation/01-soc-master-playbook.md`](../soar-automation/01-soc-master-playbook.md#sample-output).
