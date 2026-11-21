# Detection 09 — Credential Dumping: LSASS Access

| | |
|---|---|
| **MITRE ATT&CK** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Data Source** | Sysmon, Event ID 10 (ProcessAccess) |
| **Severity Logic** | Always High |

## Rationale

`lsass.exe` holds credential material in memory for every logged-on user on a Windows system. Tools like Mimikatz extract plaintext passwords and hashes by opening a handle to this process with specific memory-read access rights — this detection watches for exactly that handle request, rather than trying to fingerprint any particular tool by name or hash (which is trivially evaded by recompiling or renaming the tool).

## Detection Logic

```spl
index=sysmon EventID=10
| rex field=_raw "TargetImage'>(?<TargetImage>[^<]+)"
| rex field=_raw "SourceImage'>(?<SourceImage>[^<]+)"
| rex field=_raw "GrantedAccess'>(?<GrantedAccess>[^<]+)"
| rex field=_raw "Computer>(?<Computer>[^<]+)"
| search TargetImage="*lsass.exe"
| search NOT SourceImage IN ("*MsMpEng.exe", "*lsass.exe", "*svchost.exe", "*wininit.exe", "*NisSrv.exe", "*vmtoolsd.exe", "*WmiPrvSE.exe", "*vmware*", "*vmacthlp.exe", "*csrss.exe")
| search GrantedAccess IN ("0x1fffff", "0x1010", "0x1410", "0x143a", "0x1438")
| stats count as access_count, values(GrantedAccess) as granted_access, min(_time) as first_seen, max(_time) as last_seen by Computer, SourceImage, TargetImage
| eval mitre_technique="T1003.001 - LSASS Memory"
| eval alert_name="Credential Dumping - LSASS Access Detected"
| eval severity="High"
| convert ctime(first_seen) ctime(last_seen)
| eval granted_access_str=mvjoin(granted_access, ", ")
| eval recommended_actions="Process " . SourceImage . " accessed LSASS memory with suspicious access rights (" . granted_access_str . ") on " . Computer . ".;;Verify whether " . SourceImage . " is a known credential-dumping tool (Mimikatz, ProcDump, etc.).;;Isolate " . Computer . " from the network if the process is unrecognized.;;Collect a memory image of " . Computer . " for forensic analysis.;;Reset credentials for all accounts that have logged into " . Computer . " recently."
| eval alert_type="lsass_dump", source_ip="N/A (host-level event)", target_identity="N/A (process-level event)", host=Computer
| table alert_name, alert_type, mitre_technique, severity, host, target_identity, source_ip, SourceImage, TargetImage, granted_access_str, access_count, first_seen, last_seen, recommended_actions
```

### Why it's built this way

- **`GrantedAccess` filtering to a specific set of hex access masks** (`0x1fffff`, `0x1010`, `0x1410`, `0x143a`, `0x1438`) is the core of this detection. These correspond to Windows access rights combinations that include `PROCESS_VM_READ` and similar memory-reading permissions — the rights actually needed to dump credentials — as opposed to the far more common, benign access rights (like `PROCESS_QUERY_LIMITED_INFORMATION` alone) that many legitimate monitoring tools request against every process on the system, including LSASS.
- **The `SourceImage` exclusion list is deliberately specific to this lab's environment** — it includes Windows Defender (`MsMpEng.exe`), core OS processes, and **VMware Tools processes** (`vmtoolsd.exe`, `vmacthlp.exe`) specifically, because VMware's guest integration tools legitimately query LSASS-adjacent handles on a virtualized endpoint and would otherwise generate constant false positives in this specific lab setup.
- **No frequency threshold — a single qualifying access event fires the alert.** Unlike brute force or port scanning, there is no "acceptable" number of times an unrecognized process should open a high-privilege handle to LSASS; one occurrence is already actionable.

## Validation Note

`target_identity` is deliberately set to `"N/A (process-level event)"` rather than a user account — this event describes a *process-to-process* interaction, and attributing it to "whoever was logged in at the time" would overstate what the raw telemetry actually proves without additional correlation (e.g., joining against a concurrent 4688 process-creation event for `SourceImage`).
