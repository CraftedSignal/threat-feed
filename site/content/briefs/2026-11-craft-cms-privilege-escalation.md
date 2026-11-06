---
brief_id: brief-2026-11-06-craft-cms-privilege-escalation
event_id: brief-2026-11-06-craft-cms-privilege-escalation
revision: 1
activity_at: "2026-11-06T17:23:55Z"
title: 'Craft CMS: Privilege escalation via getOwners() (CVE-2026-123490)'
slug: 2026-11-craft-cms-privilege-escalation
description: Craft CMS versions 5.8.17 through 5.11.1 contain a privilege escalation vulnerability in the getOwners() method that allows authenticated users to promote accounts to administrator status.
date: "2026-11-06T17:23:55Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
vendors:
  - Craft CMS
products:
  - Craft CMS (5.8.17 - 5.11.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated control panel users can invoke attacker-selected static PHP callables via crafted criteria to promote every account to administrator.
    confidence_band: high
cves:
  - id: CVE-2026-123490
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123490
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Craft CMS to version 5.11.2 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-123490 remediation guidance
  hunt_leads:
    - lead: Hunt for unauthorized administrative user role assignments or modifications in application logs
      technique_id: T1068
      data_needed:
        - Craft CMS application audit logs
        - Database change logs for users table
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows authenticated users to promote any account to administrator status.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Craft CMS 5.11.2
      owner: IT Operations
      addresses: CVE-2026-123490
      evidence: NVD vulnerability details
---

Craft CMS versions 5.8.17 through 5.11.1 are vulnerable to a privilege escalation flaw (CVE-2026-123490) within the getOwners() method. The vulnerability arises because the method applies caller criteria without proper sanitization of query configuration. An authenticated user with control panel access can supply crafted criteria to trigger arbitrary static PHP callables, leading to unauthorized account privilege elevation.

## Impact

Successful exploitation allows an authenticated user with control panel access to elevate their own or any other user's account to administrative privileges.

## Recommendation

- Upgrade Craft CMS to version 5.11.2 or later immediately to include the required sanitization patches for query criteria.
- Audit control panel user accounts for suspicious administrative role assignments created or modified recently.
- Monitor logs for unusual requests directed at administrative endpoints or criteria-based search/query parameters within the Craft CMS control panel.
