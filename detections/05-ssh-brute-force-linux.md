# Detection 05 — SSH Brute Force Detected (Linux / Azure)

| | |
|---|---|
| **MITRE ATT&CK** | T1110.001 — Password Guessing |
| **Data Source** | `auth.log` from a public Azure VM, ingested via Splunk HTTP Event Collector |
| **Severity Logic** | ≥20 attempts → Critical, ≥10 → High, else Medium |

## Attack Simulated

From Kali, failed SSH logons were generated against the Azure VM's public IP (`9.205.31.174`) using a wrong password against three different usernames in a loop:

```bash
for user in alice bob charlie; do
    sshpass -p "wrongpass123" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 $user@9.205.31.174
done
```

Targeting **three different, non-existent usernames** from the same source — rather than repeatedly guessing passwords for one account — was deliberate: it validates the `dc(target_user) >= 3` branch of the detection logic below, which reclassifies this pattern as password spraying / user enumeration rather than classic single-account brute force. The resulting `auth.log` entries were forwarded to Splunk over the secure `ngrok` tunnel into the local HEC endpoint (see [`cloud-integration/`](../cloud-integration)).

## Detection Logic

```spl
index=azure sourcetype=linux_secure ("Failed password" OR "Invalid user")
| rex "(?:Failed password for(?: invalid user)? |Invalid user )(?<target_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| where isnotnull(src_ip)
| stats count as failed_attempts, dc(target_user) as unique_users, values(target_user) as target_users, min(_time) as first_seen, max(_time) as last_seen by host, src_ip
| where failed_attempts >= 3
| eval attack_type=if(unique_users>=3, "Password Spraying / User Enumeration", "SSH Brute Force")
| eval severity=case(failed_attempts>=20,"Critical", failed_attempts>=10,"High", true(),"Medium")
| eval mitre_technique="T1110.001 - Password Guessing"
| eval alert_name="SSH Brute Force Detected (Linux)"
| convert ctime(first_seen) ctime(last_seen)
| eval target_users_str=mvjoin(target_users, ", ")
| eval alert_type="ssh_bruteforce", source_ip=src_ip, target_identity=target_users_str
| eval recommended_actions=if(attack_type=="SSH Brute Force",
    "Check the reputation of the source IP (" . src_ip . ") on threat intel platforms;;Verify if the user(s) (" . target_users_str . ") had any successful logins on " . host . " shortly after these failed attempts;;If necessary, block the source IP on the perimeter firewall",
    "Password spraying detected: investigate authentication logs for broader activity targeting multiple accounts;;Check the reputation of the source IP (" . src_ip . ") on threat intel platforms;;Immediately block the source IP (" . src_ip . ") on the firewall;;Ensure MFA is enforced for the targeted users: " . target_users_str)
| table alert_name, alert_type, mitre_technique, attack_type, severity, host, target_identity, source_ip, failed_attempts, unique_users, first_seen, last_seen, recommended_actions
```

### Why it's built this way

- **A single `rex` pattern handles two distinct SSH log message formats** (`Failed password for invalid user X from Y` vs. `Invalid user X from Y`) using an optional non-capturing group, rather than requiring two separate detections for what is operationally the same event.
- **`dc(target_user) >= 3` reclassifies the attack type**, not just its severity: many failed attempts against *one* username is classic brute force, but many failed attempts spread across *several* usernames from the same source is password spraying / user enumeration — a materially different technique with different likely intent, and the `recommended_actions` text changes accordingly.
- This is the only detection whose data arrives via **HEC over the internet** rather than a Universal Forwarder on the internal LAN — proving the detection pipeline (not just the raw connectivity) works correctly for a hybrid/cloud-sourced log, including correct field extraction and alerting.

## Alert Configuration

| Setting | Value |
|---|---|
| Schedule | Cron `*/5 * * * *` (every 5 minutes) |
| Search window | Last 5 minutes |
| Expires | 24 hours |
| Trigger condition | Number of results > 0 |
| Trigger | **Once** per run |
| Throttle | ✅ Enabled |
| **Suppress results containing field value** | `source_ip` |
| Suppress triggering for | 30 minutes |
| Trigger Actions | Add to Triggered Alerts (**Severity: High**) + **Webhook** → Shuffle `SOC-Master-Playbook` |

## Validation

The three-username loop against the Azure VM appeared in `index=azure sourcetype=linux_secure` and correctly populated `target_users` (`alice, bob, charlie`) and `src_ip`; the detection correctly classified the attempt as `Password Spraying / User Enumeration` (not plain brute force) given the `unique_users >= 3` condition, and fired a live scheduled alert within one 5-minute cycle — confirming the full chain: Kali → Azure VM (public internet) → systemd forwarder → ngrok tunnel → Splunk HEC → scheduled search → alert → webhook.

See [`cloud-integration/azure-ngrok-hybrid-monitoring.md`](../cloud-integration/azure-ngrok-hybrid-monitoring.md) for how the log forwarding itself was built.
