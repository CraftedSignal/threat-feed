---
title: SQL Injection Vulnerability in Cisco Unified Intelligence Center
slug: 2026-08-cisco-uic-sqli
description: A vulnerability in the Cisco Unified Intelligence Center allows a remote, authenticated attacker to perform a SQL injection attack due to insufficient input validation.
date: "2026-08-20T13:11:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - sqli
  - vulnerability
  - cisco
vendors:
  - Cisco
products:
  - Unified Intelligence Center
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability in the Cisco Unified Intelligence Center allows a remote, authenticated attacker to perform a SQL injection attack.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2935
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Cisco Unified Intelligence Center according to vendor security advisory.
      owner: IT Operations
      due: 72h
      evidence: General security best practice for identified software vulnerabilities.
  mitigation_plan:
    - priority: immediate
      action: Review and audit all accounts with access to the Cisco Unified Intelligence Center dashboard.
      owner: SOC
      addresses: Authenticated SQL injection vector
      evidence: Vulnerability requires authenticated access to exploit.
---

Cisco has disclosed a security vulnerability affecting Cisco Unified Intelligence Center (CUIC). The flaw allows a remote, authenticated attacker to execute arbitrary SQL commands against the underlying database. The vulnerability arises from improper neutralization of special elements used in an SQL command during input processing. Because the attack requires prior authentication, the impact is limited to users who have successfully compromised or obtained legitimate credentials within the environment. Successfully exploiting this vulnerability could allow an attacker to bypass security restrictions, access unauthorized data, or modify database contents. Defenders should prioritize auditing internal access controls to the CUIC platform and monitor database query logs for anomalous patterns originating from the application's service account.

## Impact

Successful exploitation allows for unauthorized data access or modification within the Cisco Unified Intelligence Center database. This vulnerability affects enterprise organizations utilizing CUIC for reporting and analytics, potentially leading to the compromise of sensitive operational data stored within the reporting environment.

## Recommendation

* Review the official Cisco security advisory for patch availability and apply the recommended firmware or software updates for Cisco Unified Intelligence Center immediately.
* Implement strict access control lists (ACLs) to limit access to the CUIC interface to authorized personnel only, reducing the risk of a compromised account performing this attack.
* Enable database query logging on the backend database used by CUIC to monitor for unexpected SQL syntax, such as union-based or error-based injection patterns.
