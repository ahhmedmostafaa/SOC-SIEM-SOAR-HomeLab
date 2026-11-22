# Enrich-IP

A reusable sub-workflow called by any branch of the [`SOC-Master-Playbook`](./01-soc-master-playbook.md) whose alert carries a `source_ip` worth checking — brute force, RDP, port scan, and SSH brute force all invoke this same logic rather than each reimplementing their own IP-reputation lookup.

## Workflow Steps

```
Check ip type  →  AbuseIPDB v2  →  VirusTotal v3  →  Format result
```

### 1. Check ip type

Before spending an API call on either reputation service, the IP is evaluated to determine whether it falls within a private (RFC 1918) range — `192.168.x.x`, `10.x.x.x`, `172.16–31.x.x` — or is a public, internet-routable address.

**Why this check exists:** several alerts in this lab (e.g., Kerberoasting, where the client address is almost always internal) would otherwise send an internal lab IP to public threat-intelligence APIs, which is both pointless (an internal IP has no public reputation to look up) and wasteful of limited free-tier API quota. Internal IPs are short-circuited straight to `Format result` with a `N/A (private range)` placeholder instead.

### 2. AbuseIPDB v2

For public IPs only, queries AbuseIPDB for a confidence-of-abuse score (0–100%) associated with the address — flags known-malicious scanning/brute-force source IPs that have been previously reported by other users of the service.

### 3. VirusTotal v3

Also for public IPs, queries VirusTotal for a malicious-detection count — how many security vendors flag this IP as associated with malware, phishing, or other malicious infrastructure.

### 4. Format result

Combines both scores into a single, consistently-shaped output (e.g., `AbuseIPDB Score: 0%`, `VirusTotal Malicious: 0`) regardless of which upstream branch called this sub-workflow — so every notification downstream can reference the same two field names without needing to know or care which specific alert type triggered the enrichment.

## Why a Separate, Reusable Sub-Workflow Rather Than Inline Logic

Four different alert branches in the Master Playbook need IP reputation data. Implementing this logic once, as a callable sub-workflow, rather than pasting the same three API-call sequence into four different branches, means an API key rotation, a rate-limit handling fix, or a switch to a different threat-intel provider only has to happen in one place.
