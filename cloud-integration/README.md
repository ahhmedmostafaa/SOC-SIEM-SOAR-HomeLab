# Hybrid Cloud Monitoring

Every other data source in this lab lives on an isolated internal network with no path to the public internet. This section deliberately breaks that pattern: it extends the same Splunk instance to monitor a **public-facing Azure VM**, simulating the reality that most organizations today aren't purely on-prem — they have to correlate telemetry from cloud assets alongside internal infrastructure, often across network boundaries that aren't straightforward to bridge.

## The Core Constraint

The lab has no public IP and no router access to configure port forwarding. A cloud VM therefore has no direct way to reach the local Splunk instance to deliver its logs — the opposite of the internal lab, where every forwarder simply talks to `192.168.10.20` on a private network. Solving this constraint, rather than working around it by abandoning the cloud integration or faking the data locally, is the actual point of this section.

## What's Documented Here

| File | Covers |
|---|---|
| [`01-azure-vm-deployment.md`](./01-azure-vm-deployment.md) | Getting a no-credit-card Azure subscription, setting a cost safety net, and the real deployment troubleshooting (region/SKU availability) encountered along the way |
| [`02-hybrid-log-forwarding.md`](./02-hybrid-log-forwarding.md) | Exposing Splunk's HTTP Event Collector through a secure tunnel, and building a lightweight log-forwarding service on the Azure VM itself |

## Result

A dedicated detection — [SSH Brute Force Detected (Linux)](../detections/05-ssh-brute-force-linux.md) — runs against this pipeline exactly like any other detection in this lab, proving the hybrid connection isn't just "data arrives somehow" but a fully integrated source: ingested, parsed, alerted on, and routed into the same SOAR automation layer as every internal detection.
