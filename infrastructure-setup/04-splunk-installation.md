# 04 — Splunk Enterprise: Installation, Indexing & Log Forwarding

## Goal

Stand up a working SIEM pipeline: install Splunk Enterprise, structure indexes sensibly rather than dumping everything into `main`, forward telemetry from every endpoint and the firewall, and enable an HTTP ingestion path (HEC) for later hybrid-cloud monitoring.

## Platform

| Component | Detail |
|---|---|
| Host OS | Ubuntu Server 22.04 LTS (`LAB-SPLUNK1`, 192.168.10.20) |
| Splunk version | Splunk Enterprise 10.6.1.1 |
| License | Enterprise Trial (60-day) |
| Run-as user | Dedicated `splunk` system account (not root) |

### Why a dedicated Linux user?
Running Splunk as `root` is a common shortcut but a poor security practice. A dedicated `splunk` user was created, and ownership of `/opt/splunk` assigned to it before first start, so the service runs with least privilege:

```bash
sudo useradd -m -s /bin/bash splunk
sudo tar xzf splunk-*.tgz -C /opt
sudo chown -R splunk:splunk /opt/splunk
sudo -u splunk /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start -user splunk
```

## Index Structure

Rather than indexing everything into Splunk's default `main` index, dedicated indexes were created per data source — this keeps retention, permissions, and search performance manageable as the lab grows, and mirrors how a real Splunk deployment is structured:

| Index | Source | Max Size |
|---|---|---|
| `wineventlog` | Windows Security / System / Application / PowerShell logs | 10 GB |
| `sysmon` | Sysmon telemetry (all endpoints) | 10 GB |
| `pfsense` | pfSense firewall syslog | 5 GB |
| `azure` | HEC-ingested data from the Azure VM | (default) |

Max sizes were deliberately set well below Splunk's 488 GB default — the lab disk is only 48 GB total, and an unbounded index size risks Splunk halting ingestion when free disk space runs low.

## Universal Forwarder Deployment

Splunk Universal Forwarder (matching the 10.6.1.1 Enterprise version) was installed on `LAB-DC1`, `LAB-WS10`, and `LAB-WS11`, each pointed at the indexer on `192.168.10.20:9997`.

### `inputs.conf` (identical across all three Windows forwarders)

```ini
[WinEventLog://Security]
index = wineventlog
disabled = 0

[WinEventLog://System]
index = wineventlog
disabled = 0

[WinEventLog://Application]
index = wineventlog
disabled = 0

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
index = wineventlog
disabled = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = sysmon
renderXml = true
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
disabled = 0
```

## HTTP Event Collector (HEC)

HEC was enabled to allow data ingestion over HTTPS — the mechanism later used to bring in logs from a public Azure VM (see [`cloud-integration/`](../cloud-integration)).

| Setting | Value |
|---|---|
| Port | 8088 |
| SSL | Enabled |
| Token name | `azure-vm-token` |
| Target index | `azure` |

Validated with a manual event before trusting any remote source:

```powershell
$headers = @{ "Authorization" = "Splunk <token>" }
$body = @{ event = "test from local machine" } | ConvertTo-Json
Invoke-RestMethod -Uri "https://192.168.10.20:8088/services/collector/event" -Method Post -Headers $headers -Body $body
```

## Validation Checklist

- [x] `index=* | stats count by host, index` shows events from `LAB-DC1`, `LAB-WS10`, `LAB-WS11`, pfSense, and the Azure VM (see [`cloud-integration/`](../cloud-integration)).
- [x] `index=sysmon EventCode=1` returns populated `Image`, `CommandLine`, and `ParentImage` fields — confirming the Sysmon add-on parses the XML events correctly (not just raw, unparsed text).
- [x] `index=wineventlog EventCode=4688` returns a full `Process_Command_Line`, confirming the audit-policy command-line logging from the previous stage is actually reaching Splunk.
- [x] HEC accepts and indexes a manually-sent test event.

### Ingestion at Scale

As of the latest check, `index=* | stats count by host, index` reports **537,638 total events** across every source feeding the lab:

| Host | Index | Event Count |
|---|---|---|
| LAB-DC1 | wineventlog | 194,070 |
| LAB-DC1 | sysmon | 98,083 |
| LAB-WS10 | wineventlog | 124,439 |
| LAB-WS10 | sysmon | 55,554 |
| LAB-WS11 | wineventlog | 37,532 |
| LAB-WS11 | sysmon | 11,977 |
| pfSense (192.168.10.1) | pfsense | 15,772 |
| soc-cloud-vm (Azure) | azure | 208 |

This is cited deliberately: it demonstrates the pipeline isn't a one-off proof-of-concept that ingested a handful of test events, but a continuously-running SIEM that has been generating, forwarding, and indexing real telemetry across every host in the lab over an extended period.

## Lessons Learned

- **Disk space discipline matters more than expected.** An abrupt VMware shutdown (triggered by the host disk filling up during unrelated ISO downloads) corrupted a single Sysmon bucket later discovered during a threat hunt — 57 events out of 81,000+ were affected. This was investigated and confirmed isolated rather than ignored or over-reacted to (see [`threat-hunting/`](../threat-hunting)), but the root cause (snapshot sprawl filling the host disk) led to an ongoing practice of deleting stale VM snapshots after each major milestone.
- **Time zone consistency was a prerequisite, not an afterthought.** Standardizing every machine to UTC before relying on Splunk's timeline features avoided several hours of confusing, apparently-out-of-order events during later investigation work.
- **A corrupted download can silently break licensing/startup.** An initial attempt to download Splunk via a community-shared `wget` link (as an alternative while the official trial signup was pending manual review) was abandoned in favor of waiting for the official 10.6.1.1 release — worth noting as a reminder to prefer vetted, current distribution channels over third-party mirrors even when they are technically faster to obtain.
