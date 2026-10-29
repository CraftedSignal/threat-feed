---
brief_id: brief-2026-10-29-dhs-leak
event_id: brief-2026-10-29-dhs-leak
revision: 1
activity_at: "2026-10-29T13:47:01Z"
title: 'Department of Homeland Security: Massive data exfiltration of workforce and internal systems (Icepick)'
slug: 2026-10-dhs-leak
description: An entity identifying as the 'Department of Peace' exfiltrated and leaked sensitive DHS records involving 41,000 personnel and internal system configurations, reportedly obtained via the DHS Okta login portal.
date: "2026-10-29T13:47:01Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Department of Peace
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source corroborated by reporting; requires internal DHS forensic validation.
tags:
  - data-leak
  - identity-compromise
  - exfiltration
  - federal
vendors:
  - Department of Homeland Security
products:
  - Okta (DHS instance)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: DDoSecrets published the archive, which it calls 'Icepick,' on Wednesday. In a press release, DDoSecrets says the data is from DHS's Okta login system.
    confidence_band: high
references:
  - https://arstechnica.com/security/2026/10/massive-leak-exposes-41000-dhs-workers-and-undercover-ice-agents/
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Audit Okta logs for mass data retrieval or anomalous API activity correlated with the August 19, 2026 timeframe.
      owner: SOC
      due: 24h
      evidence: The records, which span DHS itself as well as seven component agencies... were last updated on August 19, 2026.
  enrichment_needed:
    - item: Identify specific credentials or service accounts accessed during the timeframe.
      owner: CTI
      reason: Necessary to prevent continued unauthorized access and mitigate further exfiltration.
      evidence: Attacker claims of access via Okta login system.
  hunt_leads:
    - lead: Search for anomalous authentication events or unusual API keys being used to query directory services.
      technique_id: T1530
      data_needed:
        - Okta System Log
        - Identity provider authentication logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: DDoSecrets says the data is from DHS's Okta login system.
  mitigation_plan:
    - priority: immediate
      action: Force a global password reset and re-authentication for all privileged accounts identified in the leaked scope.
      owner: IT Operations
      addresses: Account takeover risk
      evidence: 41,000 employees or contractors exposed
  gaps:
    - Lack of forensic visibility into the specific account(s) used for the initial unauthorized access.
---

A threat group calling itself the "Department of Peace" has leaked a large archive of Department of Homeland Security (DHS) records, dubbed "Icepick," containing the personal information of 41,000 employees and contractors. The leaked data includes email addresses, phone numbers, office locations, reporting hierarchies, and references to sensitive internal programs, including undercover operations, surveillance initiatives (e.g., CICTO, ISIP), and specialized access groups. The attackers claim the data originated from DHS's Okta environment. Okta has issued a statement denying any compromise of its own systems, suggesting the breach likely occurred via credential compromise or configuration issues within the DHS deployment.

## Impact

The exposure provides a structural map of DHS operations, identifying individual personnel involved in undercover surveillance (e.g., "CUC" and "Keyhole" programs) and access to sensitive tools such as Palantir Falcon and PenLink. This data increases the risk of targeted impersonation, reconnaissance of DHS investigative workflows, and potential physical or digital threats to exposed undercover operatives.

## Recommendation

- Perform an immediate audit of all administrative and privileged access roles within the organization's Okta or Identity Provider (IdP) environment.
- Review and rotate credentials for any service accounts or privileged users observed in external leak monitoring services that correspond to high-risk DHS or similar federal sector roles.
- Conduct an audit of external-facing system logs for patterns of anomalous authentication or mass data export from centralized identity and access management portals.
- Identify personnel with elevated access to sensitive investigative platforms and ensure Multi-Factor Authentication (MFA) is strictly enforced and verified against hardware-based security keys where possible.
