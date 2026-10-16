---
title: Authentication Bypass in IceCMS via Shiro JWT Filter Misconfiguration
slug: 2026-10-icecms-auth-bypass
description: IceCMS versions through 4.1.5 contain a missing authentication vulnerability allowing unauthenticated attackers to perform full account takeover via the /User/updateUser API endpoint.
date: "2026-10-16T18:45:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:icecms:icecms:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cms
  - web-application
vendors:
  - IceCMS
products:
  - IceCMS (<= 4.1.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IceCMS through 4.1.5 contains a missing authentication vulnerability that allows unauthenticated attackers to modify, delete, or disable any account.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078.001
    technique_name: 'Valid Accounts: Default Accounts'
    evidence: Attackers can send PUT requests to /User/updateUser to set a new password and role on any userId, including administrators.
    confidence_band: high
cves:
  - id: CVE-2026-111673
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111673
rules:
  - title: Detect CVE-2026-111673 Exploitation - Unauthenticated PUT request to /User/updateUser
    description: Detects exploitation of CVE-2026-111673 where an unauthenticated PUT request is made to the updateUser endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch IceCMS to the version resolving CVE-2026-111673
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
    - action: Deploy detection rule for PUT /User/updateUser
      owner: SOC
      due: 24h
      evidence: Detection engineering requirement
  mitigation_plan:
    - priority: immediate
      action: Restrict external access to /User/ endpoints via WAF
      owner: IT Operations
      addresses: CVE-2026-111673
      evidence: Source documentation of missing authentication in /User/ directory
---

IceCMS versions up to and including 4.1.5 contain a critical missing authentication vulnerability arising from an improper configuration of the Apache Shiro JWT filter. The application incorrectly excludes the /User/ URL path from authentication requirements, which facilitates unauthorized access to administrative functions. 

Attackers can exploit this flaw by sending unauthenticated PUT requests to the /User/updateUser endpoint. This vulnerability permits the modification of any user account identified by its userId. An attacker can leverage this to reset passwords or escalate privileges by assigning administrative roles to arbitrary user accounts, resulting in full account takeover. The vulnerability carries a CVSS v3.1 base score of 9.8, necessitating immediate attention for any organizations hosting instances of IceCMS.

## Impact

Successful exploitation of this vulnerability results in full account takeover, allowing attackers to modify, delete, or disable any account within the IceCMS system. By resetting passwords and elevating privileges for arbitrary user IDs, unauthorized actors can gain complete administrative control over the application, leading to unauthorized data access, system configuration changes, and potential exfiltration or destruction of sensitive information stored within the CMS.

## Recommendation

- Upgrade to a patched version of IceCMS immediately.
- Review all administrative accounts for suspicious modification timestamps or role changes occurring after the date of this disclosure.
- Inspect server access logs for anomalous PUT requests directed to the /User/updateUser endpoint originating from untrusted network sources.
- If immediate patching is not possible, apply a temporary WAF rule to block or challenge all incoming requests to the /User/ directory that do not possess a valid authentication token.
