---
title: Improper Privilege Management in Soarkey StudentManagement
slug: 2026-09-soarkey-privilege-escalation
description: The RegisterServlet component in Soarkey StudentManagement is vulnerable to improper privilege management, allowing remote attackers to manipulate user account levels during registration via the 'level' argument.
date: "2026-09-14T15:33:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:soarkey:studentmanagement:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - privilege-escalation
vendors:
  - Soarkey
products:
  - StudentManagement (up to e08f7f1d5015af407aa4cca0ada3dea189b4937e)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Such manipulation of the argument level leads to improper privilege management.
    confidence_band: high
cves:
  - id: CVE-2026-90787
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90787
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review web server logs for HTTP POST requests to register.html with modified level parameters
      owner: SOC
      due: 24h
      evidence: Source document identifies register.html and doPost method as the vulnerability location
  mitigation_plan:
    - priority: immediate
      action: Disable self-registration or implement WAF input validation on the level parameter
      owner: IT Operations
      addresses: CVE-2026-90787
      evidence: Public exploit available
---

A security vulnerability (CVE-2026-90787) exists in the Soarkey StudentManagement application, specifically within the Registration Workflow component. The issue resides in the 'RegisterServlet.doPost' function located in 'code/WebContent/register.html'. The application fails to adequately validate the 'level' argument provided during the registration process. This flaw allows a remote, unauthenticated attacker to inject or manipulate the account privilege level, potentially granting unauthorized elevated access. 

The project uses commit hashes rather than formal versioning, and the vulnerability affects versions up to 'e08f7f1d5015af407aa4cca0ada3dea189b4937e'. As of the report date, the vendor has been notified but has not provided a patch or formal response. Given that exploit code is publicly available, organizations running this software are at risk of account takeover and unauthorized administrative access.

## Impact

Successful exploitation allows remote attackers to register accounts with arbitrary privilege levels. This could result in complete system compromise if the attacker elevates their account to administrative status, leading to unauthorized access to student records, modification of data, or further exploitation of the underlying system infrastructure.

## Recommendation

1. Review web server access logs for anomalous HTTP POST requests to 'register.html' or associated servlet endpoints containing an unexpected 'level' parameter.
2. Implement strict input validation or temporary WAF rules to sanitize and restrict the 'level' parameter to expected integer ranges or predefined roles.
3. If immediate patching is not possible, disable the self-registration functionality until the vendor provides an official update.
4. Audit existing user account levels for suspicious privilege assignments that do not align with expected user roles.
