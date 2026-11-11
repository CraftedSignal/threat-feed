---
brief_id: brief-2026-11-11-microsoft-power-apps-info-disclosure
event_id: brief-2026-11-11-microsoft-power-apps-info-disclosure
revision: 1
activity_at: "2026-11-11T15:57:18Z"
title: 'Microsoft Power Apps: Information disclosure vulnerability'
slug: 2026-11-microsoft-power-apps-info-disclosure
description: A vulnerability in Microsoft Power Apps for the Dynamics CRM platform allows a remote, authenticated attacker to perform unauthorized information disclosure.
date: "2026-11-11T15:57:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Awaiting specific Microsoft security update link to confirm affected versions and remediation
vendors:
  - Microsoft
products:
  - Power Apps
  - Dynamics CRM
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4486
action_plan:
  priority: enrich_before_decision
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory all public-facing Power Apps and Dynamics CRM instances
      owner: SOC
      due: 24h
      evidence: Source identifies vulnerability in Power Apps for Dynamics CRM
  hunt_leads:
    - lead: Monitor Dynamics CRM audit logs for unusual data access patterns or unauthorized bulk data exports by authenticated users
      data_needed:
        - Dynamics CRM audit logs
        - Power Apps administration logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies vulnerability as information disclosure requiring authenticated attacker
---

Microsoft has identified a vulnerability in the Microsoft Power Apps integration for the Dynamics CRM platform. A remote, authenticated attacker can exploit this flaw to gain unauthorized access to sensitive information. As of the current advisory, no further technical details regarding the exploit path or the specific mechanism of disclosure have been disclosed.

## Recommendation

Prioritize reviewing the official Microsoft security updates and apply relevant patches to the Dynamics CRM and Power Apps environments once available. Monitor administrative logs for unauthorized access or unusual data export activity from the Power Apps portal.
