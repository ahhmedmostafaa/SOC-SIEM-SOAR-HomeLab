# Infrastructure Setup

Everything in this lab — every detection, every hunt, every automated response — depends on a working foundation underneath it: an isolated network, a real Active Directory domain, endpoint telemetry that actually captures what an attacker does, and a SIEM that can ingest and index it all. This folder documents that foundation, in the order it was actually built.

## Build Order

| # | File | Covers |
|---|---|---|
| 1 | [`01-network-and-pfsense.md`](./01-network-and-pfsense.md) | VMware virtual network design, pfSense firewall configuration, firewall logging, and automatic hostname resolution for firewall events |
| 2 | [`02-active-directory.md`](./02-active-directory.md) | The `soclab.internal` domain: OU structure, security groups, user accounts, domain-joined machines, DNS, and time synchronization |
| 3 | [`03-sysmon-and-audit-policy.md`](./03-sysmon-and-audit-policy.md) | The Group Policy Object that enables command-line logging, PowerShell script-block logging, and the full Advanced Audit Policy — plus Sysmon deployment with the SwiftOnSecurity configuration |
| 4 | [`04-splunk-installation.md`](./04-splunk-installation.md) | Splunk Enterprise installation, index structure, Universal Forwarder deployment, HTTP Event Collector setup, and real ingestion-volume validation |

This order matters: each stage is a hard prerequisite for the next. There is no point configuring Sysmon before the domain exists to deploy it through, and no point installing Splunk before there's any meaningful telemetry for it to ingest.

## Why This Foundation Took as Much Effort as the Detections Themselves

It's tempting to treat infrastructure setup as "just the boring part before the real work." In practice, most of what makes a detection actually work — or silently fail to fire — traces back to a decision made at this layer:

- A detection depending on `Process_Command_Line` is worthless without the audit-policy setting in [`03`](./03-sysmon-and-audit-policy.md) that makes Windows log it in the first place.
- A detection correlating a source IP against a firewall rule depends on the logging rule configured in [`01`](./01-network-and-pfsense.md) actually being enabled, not just the rule existing.
- A Kerberoasting detection is meaningless without a real domain, real SPNs, and real service accounts — the structure built in [`02`](./02-active-directory.md).

Each file below also documents the real problems encountered while building it — crashed installers, misconfigured audit subcategories, clock drift, disk-space incidents — rather than presenting a sanitized, nothing-ever-went-wrong version of the build. Diagnosing and resolving exactly these kinds of issues is a large part of what a SOC/infrastructure role actually involves day to day.
