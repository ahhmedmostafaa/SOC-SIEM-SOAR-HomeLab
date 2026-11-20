# 01 — Network Design & pfSense Firewall

## Goal

Build an isolated, enterprise-style network inside VMware Workstation with three distinct zones — WAN (internet), a corporate LAN, and a dedicated attacker segment — all mediated by a pfSense firewall, so that every attack simulated in this lab has to cross a real firewall boundary and generate real firewall logs.

## Network Topology

| Virtual Switch | Type | Subnet | Purpose |
|---|---|---|---|
| VMnet8 | NAT | 192.168.180.0/24 | WAN — internet access via the host |
| VMnet5 | Host-only (custom) | 192.168.10.0/24 | Corporate LAN — domain controller, endpoints, Splunk |
| VMnet6 | Host-only (custom) | 192.168.20.0/24 | Attacker network — isolated, only reaches the LAN through pfSense rules |

Both internal switches have **DHCP disabled** and the **host virtual adapter unchecked**, so the host machine itself has no direct route into either internal network — all internal addressing is static and managed deliberately.

## pfSense Interface Assignment

| Interface | NIC | Address | Role |
|---|---|---|---|
| WAN | em0 | DHCP (via NAT) | Internet egress |
| LAN | em1 | 192.168.10.1/24 | Corporate network gateway |
| OPT1 (renamed `ATTACKER`) | em2 | 192.168.20.1/24 | Attacker network gateway |

## Key Design Decisions

- **DHCP disabled everywhere internally.** Every host in the lab has a static IP, mirroring how enterprise infrastructure (servers, domain controllers) is typically addressed, and making log correlation unambiguous.
- **Default-deny on the attacker interface.** pfSense denies all traffic from `ATTACKER` by default. An explicit **Pass** rule was added for the attacker subnet with **logging enabled**, so every connection attempt from Kali — successful or not — generates a firewall log entry sent to Splunk.
- **HTTPS admin access kept enabled** (not reverted to HTTP) when prompted during setup, for a more realistic security posture.

## Firewall Rule (ATTACKER interface)

| Field | Value |
|---|---|
| Action | Pass |
| Interface | ATTACKER |
| Protocol | Any |
| Source | ATTACKER subnet |
| Destination | Any |
| Log | ✅ Enabled |
| Description | `Lab: attacker net to all (logged)` |

## Remote Syslog to Splunk

pfSense forwards firewall events to Splunk over UDP:

- **Status → System Logs → Settings → Remote Logging**
- Remote log server: `192.168.10.20:5514`
- Content: **Firewall Events** only (to avoid flooding the index with unrelated system noise)

On the Splunk side, a UDP input was created on port `5514`, sourcetype `syslog`, indexed into a dedicated `pfsense` index.

## Validation

With pfSense, the domain controller, and Splunk running, traffic generated from Kali (`ping`, `nmap`) against the LAN was confirmed to appear in Splunk within ~1 minute:

```spl
index=pfsense | head 10
```

Raw `filterlog` events showed source/destination IPs, ports, protocol, and pass/block action — exactly the fields later used to build the **Port Scan Detection (T1046)** detection.

## Lessons Learned

- An early install of pfSense (via an older RC installer build) repeatedly crashed with a `Segmentation fault` during the final package install step, regardless of memory allocated. Switching to the current Netgate installer release resolved it — a reminder to always validate the installer version before assuming a hardware/resource issue.
- pfSense's `filterlog` format has no hostname field — only the firewall's own IP — which required either accepting `host=192.168.10.1` in Splunk or adding a lookup to map it to a friendly name (`pfSense-FW`) for cleaner dashboards.
