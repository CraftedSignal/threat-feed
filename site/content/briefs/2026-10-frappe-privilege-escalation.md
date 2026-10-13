---
title: Improper Privilege Management in Frappe Framework
slug: 2026-10-frappe-privilege-escalation
description: Frappe versions 14.x and 15.x contain a privilege management vulnerability allowing authenticated Website Users to escalate to System Manager privileges via document action manipulation.
date: "2026-10-13T00:30:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:frappe:frappe_framework:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - frappe
  - cve-2024-58390
vendors:
  - Frappe
products:
  - Frappe Framework (< 14.81.4, 15.x < 15.41.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated attackers with Website User access can combine this document action with additional steps to obtain administrative System Manager privileges in the Frappe application.
    confidence_band: high
cves:
  - id: CVE-2024-58390
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-58390
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Frappe Framework to version 14.81.4 or 15.41.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2024-58390 patch requirements
  hunt_leads:
    - lead: Audit access logs for privilege escalation by Website Users to System Manager
      technique_id: T1068
      data_needed:
        - Application access logs
        - Role change event logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Documented improper privilege management vulnerability
  mitigation_plan:
    - priority: immediate
      action: Patch Frappe to 14.81.4 or 15.41.0
      owner: IT Operations
      addresses: CVE-2024-58390
      evidence: Official vendor security patch requirement
---

Frappe Framework versions prior to 14.81.4 and 15.x prior to 15.41.0 contain a critical vulnerability related to improper privilege management. This flaw allows an authenticated attacker holding the low-privileged 'Website User' role to escalate their account permissions to the 'System Manager' level. The exploitation involves the manipulation of a specific document action within the application. By successfully executing this escalation, an attacker gains administrative control over the Frappe instance, enabling unauthorized access to application data, configuration settings, and potential further system exploitation. Because Frappe is a common back-end framework for ERPNext and other business applications, successful exploitation carries significant risk to organizational integrity and data confidentiality.

## Impact

Successful exploitation grants an attacker full System Manager privileges within the Frappe application. This provides administrative access to all documents, system configurations, and internal business logic managed by the platform. This vulnerability affects any organization utilizing self-hosted or cloud-deployed versions of Frappe Framework 14.x or 15.x within the specified version ranges. Unauthorized access of this magnitude can lead to complete data exfiltration, service manipulation, and long-term persistence within the business environment.

## Recommendation

1. Upgrade all instances of Frappe Framework to version 14.81.4 or 15.41.0 immediately to address CVE-2024-58390.
2. Review user access logs for any 'Website User' accounts that have recently modified sensitive system documents or accessed System Manager configuration endpoints.
3. Implement principle of least privilege by auditing all current 'System Manager' accounts and ensuring only authorized administrative personnel retain such access.
