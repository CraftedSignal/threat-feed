---
title: Authorization Bypass in FeatherPanel SubuserController
slug: 2026-09-featherpanel-auth-bypass
description: Authenticated subusers can exploit a permission validation failure in FeatherPanel versions before 1.3.7.10 to escalate privileges to full server control.
date: "2026-09-02T05:11:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:featherpanel:featherpanel:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - web-application
vendors:
  - FeatherPanel
products:
  - FeatherPanel (< 1.3.7.10)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The application fails to properly validate permissions, allowing an authenticated subuser to modify their own permission records and escalate their privileges to full server control.
    confidence_band: high
cves:
  - id: CVE-2026-84715
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84715
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade FeatherPanel to version 1.3.7.10
      owner: IT Operations
      due: 24h
      evidence: Source states FeatherPanel versions before 1.3.7.10 fail to validate permissions
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 1.3.7.10 or higher
      owner: IT Operations
      addresses: CVE-2026-84715
      evidence: NVD vulnerability disclosure
---

FeatherPanel versions prior to 1.3.7.10 contain a critical authorization vulnerability within the SubuserController updateSubuser handler. This vulnerability arises due to a failure to validate permissions during the update process for subuser accounts. An authenticated attacker possessing a low-privileged subuser account can submit a crafted request to the application to modify their own permission records. By manipulating these records, a subuser can grant themselves elevated administrative privileges, including full server control. This escalation allows the attacker to gain unauthorized access to sensitive server data, configuration files, and backups, effectively compromising the integrity and confidentiality of the hosting environment managed by the panel. This vulnerability is classified as an authorization bypass, allowing privilege escalation.

## Impact

Successful exploitation of this vulnerability allows low-privileged subusers to gain full administrative control over the FeatherPanel installation. This results in unauthorized access to sensitive server-side data, system configurations, and automated backups. Depending on the server deployment, this could lead to total system compromise, exfiltration of customer data, or disruption of hosted services.

## Recommendation

* Upgrade all FeatherPanel instances to version 1.3.7.10 or later immediately.
* Audit logs for suspicious activity originating from existing subuser accounts, specifically monitoring for frequent or unauthorized modification requests to the SubuserController endpoint.
* Review all current subuser privilege levels to identify unauthorized account upgrades that may have occurred prior to patching.
