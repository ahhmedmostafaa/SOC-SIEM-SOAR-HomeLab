# Detection 06 — Privileged Group Membership Change

| | |
|---|---|
| **MITRE ATT&CK** | T1098 — Account Manipulation |
| **Data Source** | Windows Security Log, Event IDs 4728 / 4732 / 4756 |
| **Severity Logic** | Domain Admins / Enterprise Admins / Schema Admins → Critical, any other admin/operators group → High |

## Attack Simulated

On `LAB-DC1`, a new user account was created and immediately added to **Domain Admins** — a classic post-compromise privilege escalation move once an attacker has obtained any foothold with account-creation rights:

```powershell
net user testuser2 Pass@word! /add /domain
net group "Domain Admins" testuser2 /add /domain
```

## Rationale

Adding an account to a privileged group is one of the clearest, highest-confidence indicators of privilege escalation or persistence in an Active Directory environment — whether the account is freshly compromised or an insider abusing legitimate access. This detection covers all three event IDs Windows uses depending on group scope (global, domain local, universal), since relying on only one would miss group-type variations.

## Detection Logic

```spl
index=* (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| rex field=_raw "Subject:\s*\n\s*Security ID:\s*\S+\s*\n\s*Account Name:\s+(?<performed_by>\S+)"
| rex field=_raw "Member:\s*\n\s*Security ID:\s*(?<member_sid>\S+)\s*\n\s*Account Name:\s+(?:CN=)?(?<added_account>[^,\r\n]+)"
| rex field=_raw "Group Name:\s+(?<group_name>.+)"
| where match(group_name, "(?i)admin|operators")
| eventstats values(eval(if(added_account!="-", added_account, null()))) as resolved_name by member_sid
| eval added_account=if(added_account="-", coalesce(resolved_name, "SID: ".member_sid), added_account)
| eval group_type=case(EventCode=4728,"Global", EventCode=4732,"Local/Domain Local", EventCode=4756,"Universal")
| eval performed_by=replace(performed_by, "\$", "")
| stats values(group_type) as group_types, values(EventCode) as event_codes, min(_time) as first_seen, max(_time) as last_seen by performed_by, added_account, group_name
| eval group_types_str=mvjoin(group_types, ", ")
| eval event_codes_str=mvjoin(event_codes, ", ")
| eval mitre_technique="T1098 - Account Manipulation"
| eval alert_name="Privileged Group Membership Change (4728/4732/4756)"
| eval severity=case(match(group_name, "(?i)domain admins|enterprise admins|schema admins"), "Critical", true(), "High")
| eval host="N/A (domain-wide event)"
| convert ctime(first_seen) ctime(last_seen)
| eval recommended_actions="A privileged group membership change was detected: " . added_account . " was added to " . group_name . ".;;Verify with " . performed_by . " whether this change was authorized.;;Check if " . added_account . " legitimately requires membership in this group.;;If unauthorized, immediately remove " . added_account . " from " . group_name . " and investigate " . performed_by . " for compromise.;;Review recent activity of " . performed_by . " for other signs of privilege escalation."
| eval alert_type="privileged_group_change", source_ip="N/A (host-level event)", target_identity=performed_by
| table alert_name, alert_type, mitre_technique, severity, host, target_identity, source_ip, added_account, group_name, group_types_str, event_codes_str, first_seen, last_seen, recommended_actions
```

### Why it's built this way

- **`where match(group_name, "(?i)admin|operators")`** filters to privileged groups only — Windows logs 4728/4732/4756 for *any* security group membership change, including completely benign departmental groups, so without this filter the detection would be far too noisy to be useful.
- **The `added_account` resolution logic (`eventstats` + `coalesce`)** solves a real Windows logging quirk: the "Member" field in these events is sometimes logged only as a SID with a blank/`-` account name on the *first* occurrence, while a later, related event in the same operation carries the resolved name. Correlating by `member_sid` across events recovers a human-readable name instead of leaving the analyst to manually resolve a raw SID.
- **Domain/Enterprise/Schema Admins are escalated to Critical** specifically, because compromise of any of these three groups is effectively full forest or domain compromise — a materially different risk tier than, say, being added to a local "Backup Operators" group on one server.

## Alert Configuration

| Setting | Value |
|---|---|
| Schedule | Cron `*/5 * * * *` (every 5 minutes) |
| Search window | Last 5 minutes |
| Expires | 24 hours |
| Trigger condition | Number of results > 0 |
| Trigger | **Once** per run |
| Throttle | ✅ Enabled |
| **Suppress results containing field value** | `added_account` |
| Suppress triggering for | 30 minutes |
| Trigger Actions | Add to Triggered Alerts (**Severity: High**) + **Webhook** → Shuffle `SOC-Master-Playbook` |

Suppressing on `added_account` — rather than on who made the change — ensures that if the same account is touched by more than one qualifying event in the suppression window (plausible here, since creating the account and adding it to Domain Admins are two separate logged operations seconds apart), it is still treated and notified as a single incident.

## Validation Note

This detection targets a **domain-wide, identity-centric event** rather than a specific host, which is why `host` is deliberately set to `"N/A (domain-wide event)"` — group membership isn't scoped to a single machine, and forcing a host value here would be misleading rather than informative.
