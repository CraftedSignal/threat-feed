---
brief_id: brief-2026-11-11-microsoft-office-vulnerabilities
event_id: brief-2026-11-11-microsoft-office-vulnerabilities
revision: 1
activity_at: "2026-11-11T13:53:23Z"
title: 'Microsoft Office and SharePoint: Multiple High-Severity Vulnerabilities'
slug: 2026-11-microsoft-office-vulnerabilities
description: The NCSC-NL has identified multiple high-severity vulnerabilities in Microsoft Office, specifically within SharePoint, which could permit unauthorized code execution, sensitive data access, or system impersonation.
date: "2026-11-11T13:53:23Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Patch installation needs verification across the server estate.
vendors:
  - Microsoft
products:
  - SharePoint
  - Microsoft Office
references:
  - https://www.ncsc.nl/alerts/ernstige-kwetsbaarheden-in-microsoft-office
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all SharePoint and Office environments using the latest security updates provided by Microsoft
      owner: IT Operations
      due: 48h
      evidence: NCSC-NL advises that the available security updates be installed as soon as possible.
  hunt_leads:
    - lead: Monitor SharePoint access logs for unusual administrative activity or successful logins from atypical IP addresses
      technique_id: T1078
      data_needed:
        - SharePoint Unified Audit Logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The advisory states that an attacker could impersonate a user and perform malicious actions.
  mitigation_plan:
    - priority: immediate
      action: Apply Microsoft security updates
      owner: IT Operations
      addresses: SharePoint and Office vulnerabilities
      evidence: Microsoft has made security updates available that address these vulnerabilities.
---

The National Cyber Security Centre (NCSC-NL) has reported multiple critical vulnerabilities affecting Microsoft Office, with three specific vulnerabilities in SharePoint rated with a CVSS score of 9.0 or higher. Attackers could potentially leverage these flaws to impersonate users, execute arbitrary code, or access sensitive information. There is no evidence of active exploitation at this time.

## Impact

Unpatched systems are at risk of arbitrary code execution, unauthorized access to sensitive information, and full system compromise. This poses a significant threat to data confidentiality and business continuity.

## Recommendation

- Immediately review internal inventory for all Microsoft Office and SharePoint instances.
- Apply security updates provided by Microsoft for all affected installations as a priority.
- Contact managed IT service providers if internal patch management processes require validation.
