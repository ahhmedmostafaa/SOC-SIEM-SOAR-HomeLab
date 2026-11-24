# Enrich-Identity

![Enrich-Identity workflow graph](./screenshots/enrich-identity.png)
*A deliberately minimal, single-step sub-workflow — identity context resolution doesn't need the multi-API chain that IP enrichment does.*

A reusable sub-workflow for alert branches centered on an **account** rather than a source IP — Kerberoasting, Privileged Group Membership Change, and Scheduled Task creation are identity-driven events where "who" matters more than "where from."

## Workflow Step

```
Check identity role
```

This step takes the alert's `target_identity` field and resolves context about the account itself: whether it corresponds to a standard user, a service account, or a privileged/administrative account (cross-referencing against the domain structure documented in [`infrastructure-setup/02-active-directory.md`](../infrastructure-setup/02-active-directory.md) — e.g., recognizing `svc.backup` as a service account, or `adm.soc` as a Domain Admin).

## Why This Matters for Triage

The same raw event (for example, a scheduled task being created) carries very different risk depending on who created it. A scheduled task created by `LAB-WS10` the machine account, during routine patching, is materially different from the same event tied to a standard user account that has no business creating SYSTEM-level scheduled tasks. Surfacing the identity's role alongside the alert — rather than leaving the analyst to look it up manually in Active Directory mid-investigation — shortens the time it takes to judge whether an alert needs urgent escalation.

## Relationship to IP Enrichment

`Enrich-Identity` and [`Enrich-IP`](./02-enrich-ip.md) are not mutually exclusive — some alerts (like Privileged Group Membership Change, which has both a `performed_by` identity and may need no IP check since it's a domain-wide event) only need identity context, while others only need IP context. The Master Playbook's router determines which sub-workflow (or both) a given branch actually calls, keeping each alert type's enrichment proportional to what the alert actually provides and needs.
