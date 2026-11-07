---
brief_id: brief-2026-11-07-ibm-api-connect-brola
event_id: brief-2026-11-07-ibm-api-connect-brola
revision: 1
activity_at: "2026-11-07T05:51:27Z"
title: 'IBM API Connect: Broken object-level authorization (CVE-2026-17292)'
slug: 2026-11-ibm-api-connect-brola
description: IBM API Connect versions 10.0.8.0-10.0.8.12 and 12.1.0.0-12.1.1.2 contain a broken object-level authorization vulnerability allowing remote authenticated attackers to seize ownership of unauthorized organizations.
date: "2026-11-07T05:51:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ibm:api_connect:*:*:*:*:*:*:*:*
tags:
  - cve-2026-17292
  - bola
  - api-security
vendors:
  - IBM
products:
  - API Connect (10.0.8.0-10.0.8.12, 12.1.0.0-12.1.1.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A remote authenticated attacker can exploit this flaw to modify ownership of organizations they do not control, effectively leading to unauthorized privilege escalation and takeover of organizational resources.
    confidence_band: high
cves:
  - id: CVE-2026-17292
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17292
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade IBM API Connect to a patched version as advised by IBM security documentation.
      owner: IT Operations
      due: 48h
      evidence: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable.
  hunt_leads:
    - lead: Monitor API Connect audit logs for unusual ownership changes of organization objects by low-privileged authenticated users.
      technique_id: T1068
      data_needed:
        - API Connect administrative audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Access checks on organization objects are incomplete, which could allow ownership of organizations the user does not control to be changed.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to non-vulnerable versions of IBM API Connect.
      owner: IT Operations
      addresses: CVE-2026-17292
      evidence: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are affected.
---

IBM API Connect contains a broken object-level authorization (BOLA) vulnerability (CVE-2026-17292) caused by incomplete access checks on organization objects. A remote authenticated attacker can leverage this flaw to modify the ownership of organizations they do not control, leading to unauthorized privilege escalation and takeover of organizational resources.

## Impact

Successful exploitation allows a remote authenticated attacker to gain full administrative control over target organizations, potentially resulting in unauthorized access to sensitive API data, configuration modifications, and full resource takeover.

## Recommendation

- Inventory all instances of IBM API Connect within the environment to identify versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2.
- Prioritize the application of vendor-supplied security patches or version upgrades as documented in official IBM security bulletins for CVE-2026-17292.
- Implement monitoring for administrative configuration changes within API Connect to detect anomalous organization ownership transfers.
