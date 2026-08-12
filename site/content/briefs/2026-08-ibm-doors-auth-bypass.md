---
title: Improper Authentication in IBM DOORS Next
slug: 2026-08-ibm-doors-auth-bypass
description: IBM DOORS Next 7.0.3 through 7.0.3 Interim Fix 018 contains an improper authentication vulnerability that allows authenticated users to bypass security logic and perform unauthorized actions.
date: "2026-08-12T22:51:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - IBM
products:
  - DOORS Next (7.0.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: IBM DOORS Next 7.0.3 through 7.0.3 Interim Fix 018 could allow an authenticated user to bypass security logic to perform unauthorized activities.
    confidence_band: high
cves:
  - id: CVE-2024-27253
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-27253
  - https://www.ibm.com/support/pages/node/7282705
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Apply latest IBM security patches for DOORS Next
      owner: IT Operations
      due: 24h
      evidence: CVE-2024-27253 advisory
  hunt_leads:
    - lead: Identify accounts performing actions outside their defined scope
      technique_id: T1068
      data_needed:
        - Application audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows bypass of security logic
---

IBM DOORS Next versions 7.0.3 through 7.0.3 Interim Fix 018 are affected by a critical vulnerability (CVE-2024-27253) identified as an improper authentication flaw (CWE-287). The vulnerability allows an authenticated user to bypass security logic within the application to perform unauthorized activities. Given the CVSS score of 10.0, this flaw potentially allows for full compromise of the application's confidentiality, integrity, and availability. Organizations utilizing these versions of IBM DOORS Next are urged to apply the latest security patches provided by IBM to remediate the authentication logic flaw.

## Impact

The vulnerability carries a CVSS 3.1 base score of 10.0, indicating the highest level of severity. Successful exploitation permits unauthorized users to bypass existing security controls, potentially leading to unauthorized data access, modification of requirements, or administrative control over the DOORS Next environment. This vulnerability primarily affects enterprise organizations utilizing IBM's requirements management software for project development and documentation.

## Recommendation

Prioritized, concrete actions for infrastructure and security teams:
- Upgrade IBM DOORS Next installations to a version strictly beyond 7.0.3 Interim Fix 018.
- Review application access logs for anomalous activity from low-privileged user accounts, specifically focusing on unauthorized access to administrative or high-sensitivity modules in DOORS Next.
- Monitor authentication logs for patterns of session manipulation or bypass attempts.
- Disable internet-facing access to the DOORS Next web interface until patching is completed to limit exposure to potential exploitation.
