# 03 — Endpoint Telemetry: Advanced Audit Policy, PowerShell Logging & Sysmon

## Goal

Default Windows logging is not enough to detect modern attack techniques — out of the box, Windows does not log process command lines, does not log PowerShell script content, and leaves most advanced audit subcategories disabled. This stage builds the **telemetry foundation** that every detection in this lab depends on, deployed centrally via Group Policy so it applies consistently across the domain controller and all endpoints.

Without this step done correctly, Splunk would have nothing meaningful to analyze — this is the single most important stage for the overall quality of the lab.

## Group Policy Object: `SOC-Audit-Policy`

A single GPO was created and linked to both the `SOCLAB` OU (covering endpoints) and the `Domain Controllers` OU (covering `LAB-DC1`), so every machine in the domain receives the same policy.

### Registry-Based Settings (applied via `Set-GPRegistryValue`)

| Setting | Purpose |
|---|---|
| `ProcessCreationIncludeCmdLine_Enabled = 1` | Forces Event ID 4688 to include the full command line of the created process — critical for detecting malicious execution |
| `SCENoApplyLegacyAuditPolicy = 1` | Forces Windows to honor the Advanced Audit Policy instead of the legacy, coarser audit categories |
| Security log `MaxSize = 512 MB` | Prevents the security log from rotating out evidence too quickly under load |
| PowerShell `EnableScriptBlockLogging = 1` | Logs the actual content of executed PowerShell script blocks — the primary way encoded/obfuscated PowerShell is caught in this lab |
| PowerShell `EnableModuleLogging = 1` with `ModuleNames = *` | Logs pipeline execution details for all PowerShell modules |

### Advanced Audit Policy Configuration

Configured under *Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration*:

| Category | Subcategory | Setting |
|---|---|---|
| Account Logon | Credential Validation | Success + Failure |
| Account Logon | Kerberos Authentication Service | Success + Failure |
| Account Logon | Kerberos Service Ticket Operations | Success + Failure |
| Account Management | Computer Account Management | Success |
| Account Management | Security Group Management | Success + Failure |
| Account Management | User Account Management | Success + Failure |
| Detailed Tracking | Process Creation | Success |
| DS Access | Directory Service Changes | Success |
| Logon/Logoff | Logon | Success + Failure |
| Logon/Logoff | Logoff | Success |
| Logon/Logoff | Account Lockout | Failure |
| Logon/Logoff | Special Logon | Success |
| Object Access | Other Object Access Events | Success + Failure |
| Policy Change | Audit Policy Change | Success |
| Policy Change | Authentication Policy Change | Success |
| Privilege Use | Sensitive Privilege Use | Success + Failure |
| System | Security State Change | Success |
| System | Security System Extension | Success |

**Why `Other Object Access Events` matters:** Scheduled Task creation (Event ID 4698) will not be logged at all without this subcategory enabled — a detail easy to miss, since it isn't in the "obvious" logon/logoff categories.

## Sysmon Deployment

**Tool:** Sysinternals Sysmon, configuration based on the **SwiftOnSecurity** template — chosen as a well-tested, high-signal starting configuration rather than writing detection rules from an empty config.

Installed identically on `LAB-DC1`, `LAB-WS10`, and `LAB-WS11`:

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive -Path Sysmon.zip -DestinationPath . -Force
Invoke-WebRequest -Uri "https://github.com/SwiftOnSecurity/sysmon-config/raw/master/sysmonconfig-export.xml" -OutFile sysmonconfig-export.xml
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### Key Sysmon Event IDs relied on by this lab's detections

| Event ID | Captures | Used in |
|---|---|---|
| 1 | Process creation (with parent, hashes, command line) | PowerShell obfuscation hunt, LOLBins hunt |
| 10 | Process access (e.g., a process opening a handle to another) | Credential Dumping — LSASS Access detection |
| 13 | Registry value set | Registry Persistence — Run Key Modified detection |

## Validation

For each endpoint, two checks confirmed the pipeline was working end-to-end *before* moving on:

```powershell
auditpol /get /subcategory:"Process Creation"
# Expected: Success

Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 5 |
    ForEach-Object { $_.Properties[8].Value }
# Expected: full command lines, not blank
```

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3 | Select TimeCreated, Id
```

## Lessons Learned

- During GPO configuration, two adjacent settings in the Advanced Audit Policy editor (**Logoff** and **Account Lockout**) were accidentally swapped — `Logoff` was set to `Failure` and `Account Lockout` left unconfigured. This was only caught by re-running `auditpol /get /category:*` and comparing every line against the intended table above, rather than assuming the GUI clicks were correct. **Takeaway:** always verify the *applied* policy with `auditpol`, not just the GPO editor's checkbox state.
- GPO changes do not take effect until `gpupdate /force` is run (or a reboot), and verification should always happen *after* that, not immediately after editing the GPO.
