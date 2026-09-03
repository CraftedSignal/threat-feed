---
title: Authentication Bypass in vhr PUT /hr/pass Endpoint
slug: 2026-09-vhr-auth-bypass
description: An authentication flaw in the vhr application through commit 03abbd3 allows authenticated attackers to perform unauthorized password changes for arbitrary accounts by manipulating the account ID in PUT requests.
date: "2026-09-03T17:22:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vhr_project:vhr:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - privilege-escalation
  - web-vulnerability
products:
  - vhr (<= 03abbd3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: Authenticated attackers can change arbitrary account passwords by supplying a target account ID and that account's current password in the request body.
    confidence_band: high
cves:
  - id: CVE-2026-85182
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85182
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch vhr to a version newer than 03abbd3.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-85182
  mitigation_plan:
    - priority: immediate
      action: Upgrade vhr to a non-vulnerable commit.
      owner: IT Operations
      addresses: CVE-2026-85182
      evidence: NVD vulnerability notice
---

The vhr application, through commit 03abbd3, contains a critical authentication vulnerability that allows an authenticated user to reset the password of any account within the system. The flaw exists within the PUT /hr/pass endpoint, which fails to enforce a proper authorization check to verify that the account ID specified in the request body matches the identity of the authenticated user performing the request. 

By supplying an arbitrary account ID along with that account's current password in the request body, an attacker can successfully overwrite the credentials for that target account. This vulnerability is highly impactful as it enables privilege escalation or total account takeover, provided the attacker has valid authentication to the platform. This issue was identified as CVE-2026-85182 and represents a failure in backend access control logic that requires immediate attention for systems running vhr versions at or below commit 03abbd3.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to gain unauthorized access to any user account on the platform, including administrative accounts. This leads to complete loss of account integrity and potential exfiltration of sensitive personnel or HR data managed by the application. Because the vulnerability allows an attacker to control the authentication credentials of any target account, the impact is severe, potentially compromising the entire instance of the vhr application.

## Recommendation

1. Patch the vhr application immediately by updating to a commit version later than 03abbd3 that includes the authorization fix for the PUT /hr/pass endpoint.
2. Implement request validation logging for the PUT /hr/pass endpoint to identify requests where the authenticated user ID differs from the account ID provided in the payload.
3. Audit application access logs for multiple password change requests originating from a single authenticated session that target different account IDs.
