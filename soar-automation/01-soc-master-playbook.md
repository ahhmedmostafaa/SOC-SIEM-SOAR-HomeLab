# SOC-Master-Playbook

The central entry point for every alert this lab's Splunk instance generates.

## Trigger

A single **Webhook** trigger node receives an HTTP POST from Splunk's "Webhook" alert action (configured identically across all ten detections — see [`detections/README.md`](../detections/README.md#shared-alert-configuration-pattern)) whenever any of the ten scheduled alerts fires.

## Why a Single Shared Payload Schema Makes This Possible

This router only works because every detection outputs the same standardized field set (`alert_type`, `severity`, `host`, `target_identity`, `source_ip`, `recommended_actions`, etc. — see [`detections/README.md`](../detections/README.md#a-standardized-alert-schema)). The router's logic is simple *because* the upstream SPL already did the work of normalizing every alert type into a consistent shape before it ever reaches Shuffle.

## Routing Logic

A **Router** node inspects the incoming `alert_type` field and dispatches the event down exactly one of ten conditional branches — one per detection:

| `alert_type` value | Routed to enrichment branch |
|---|---|
| `identity_bruteforce` | Enrich (Brute Force) |
| `kerberoasting` | Enrich Kerberoasting |
| `port_scan` | Enrich Port Scan |
| `rdp_logon` | Enrich RDP |
| `ssh_bruteforce` | Enrich SSH |
| `privileged_group_change` | Enrich Priv Group |
| `log_clearing` | Enrich Log Clearing |
| `registry_persistence` | Enrich Registry |
| `lsass_dump` | Enrich LSASS |
| `scheduled_task` | Enrich Scheduled Task |

Each branch performs whatever enrichment is relevant to *that* alert type specifically (an IP-centric alert calls the shared [`Enrich-IP`](./02-enrich-ip.md) sub-workflow; an identity-centric alert calls [`Enrich-Identity`](./03-enrich-identity.md)), then all ten branches converge back into a single shared notification stage.

## Convergence and Notification

After enrichment, every branch feeds into the same two final actions, regardless of which branch it came from:

- **Notify Telegram** — a condensed, real-time message with the key facts (alert name, severity, source IP, reputation score) and, for alerts that support remediation, inline **Block / Ignore** buttons
- **Notify SOC (Email)** — a fuller incident report with the complete field set and the alert's pre-formatted `recommended_actions` checklist

This convergence design means adding a notification channel (or changing the report format) happens once, in one place, rather than needing to be duplicated across ten separate branches.

## Design Rationale: Router vs. Ten Independent Playbooks

The alternative — one standalone Shuffle workflow per detection, each with its own webhook — was deliberately rejected. It would mean:
- Ten different webhook URLs to configure and keep track of in Splunk
- Notification formatting logic duplicated (and liable to drift out of sync) across ten workflows
- Adding a new notification channel requiring ten separate edits instead of one

The router pattern used here is the same architectural approach real SOAR deployments use for exactly this reason: one ingestion contract, branching logic for alert-specific handling, and shared logic for everything that *doesn't* need to differ by alert type.
