---
brief_id: brief-2026-11-09-intelbras-sg-authentication-bypass
event_id: brief-2026-11-09-intelbras-sg-authentication-bypass
revision: 1
activity_at: "2026-11-09T09:37:02Z"
title: 'Intelbras SG 2404 PoE L2+: Improper authentication in Web Management Interface (CVE-2026-124577)'
slug: 2026-11-intelbras-sg-authentication-bypass
description: A remote, unauthenticated authentication bypass vulnerability exists in the Web Management Interface of Intelbras SG 2404 PoE L2+ switches via the /EXCU_SHELL file, for which public exploit code is available.
date: "2026-11-09T09:37:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:h:intelbras:sg_2404_poe_l2\+:1.00.70:*:*:*:*:*:*:*
  - cpe:2.3:h:intelbras:sg_2404_poe_l2\+:1.00.72:*:*:*:*:*:*:*
vendors:
  - Intelbras
products:
  - SG 2404 PoE L2+ (1.00.70, 1.00.72)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely. The exploit has been made available to the public.
    confidence_band: high
cves:
  - id: CVE-2026-124577
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124577
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Intelbras SG 2404 PoE L2+ switches to version 1.00.74
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 1.00.74 is sufficient to fix this issue.
  hunt_leads:
    - lead: Identify HTTP requests targeting /EXCU_SHELL on Intelbras switches
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Network firewall logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The affected element is an unknown function of the file /EXCU_SHELL of the component Web Management Interface.
  mitigation_plan:
    - priority: immediate
      action: Upgrade firmware to 1.00.74
      owner: IT Operations
      addresses: CVE-2026-124577
      evidence: Upgrading to version 1.00.74 is sufficient to fix this issue.
---

A critical improper authentication vulnerability exists in the Web Management Interface of the Intelbras SG 2404 PoE L2+ switch (firmware versions 1.00.70 and 1.00.72). The vulnerability resides in an unspecified function within the /EXCU_SHELL component and allows unauthenticated remote attackers to bypass authentication. Public exploit code is available, heightening the risk of exploitation.

## Impact
Successful exploitation allows for improper authentication, which may grant unauthorized access to the device management interface. Given the CVSS 9.8 score, this access can likely lead to full device compromise.

## Recommendation
- Upgrade Intelbras SG 2404 PoE L2+ firmware to version 1.00.74 or later immediately.
- Restrict access to the device web management interface to trusted internal networks only.
- Audit network logs for unauthorized access attempts targeting the /EXCU_SHELL path.
