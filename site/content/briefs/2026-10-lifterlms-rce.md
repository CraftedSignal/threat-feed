---
title: PHP Object Injection Vulnerability in LifterLMS Plugin
slug: 2026-10-lifterlms-rce
description: The LifterLMS WordPress plugin is vulnerable to authenticated PHP Object Injection, allowing attackers with edit_course capabilities to potentially execute code if a compatible POP chain exists elsewhere in the environment.
date: "2026-10-10T07:50:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lifterlms:lifterlms:*:*:*:*:*:wordpress:*:*
vendors:
  - LifterLMS
products:
  - LifterLMS – WP LMS for eLearning, Online Courses, & Quizzes (<= 10.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The LifterLMS plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 10.2.1 via deserialization of untrusted input.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: If a POP chain is present via an additional plugin or theme installed on the target system, it may allow the attacker to perform actions like delete arbitrary files, retrieve sensitive data, or execute code.
    confidence_band: high
cves:
  - id: CVE-2026-104723
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104723
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Upgrade LifterLMS plugin to version 10.2.2 or later.
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability exists in versions up to and including 10.2.1.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict 'edit_course' capabilities for non-admin/non-instructor users.
      owner: Security Team
      addresses: CVE-2026-104723
      evidence: Exploitation requires the attacker to hold a role with the edit_course capability.
---

The LifterLMS plugin for WordPress, in versions up to and including 10.2.1, contains an insecure deserialization vulnerability identified as CVE-2026-104723. The vulnerability exists within the lesson creation process, where the plugin improperly handles untrusted input during the metadata processing phase. To exploit this, an attacker must possess an account with at least 'edit_course' capabilities, such as an Instructor or LMS Manager.

While the LifterLMS codebase itself does not contain a Property-Oriented Programming (POP) chain, the vulnerability allows an attacker to inject arbitrary PHP objects that can be exploited if other plugins or themes installed on the same WordPress instance provide the necessary gadgets. Successful exploitation, in conjunction with a separate vulnerable component, may lead to arbitrary file deletion, unauthorized data retrieval, or remote code execution. This highlights the risk posed by the aggregate attack surface of complex CMS environments where multiple plugins interact.

## Impact

The impact of this vulnerability is contingent upon the presence of auxiliary POP chains within the WordPress environment. If a chain is present, an attacker could achieve full site compromise, execute remote code, or modify sensitive system files. The vulnerability specifically targets environments using LifterLMS for course management, exposing educational institutions and online training platforms to potential data breaches and service disruption.

## Recommendation

- Upgrade LifterLMS to a version beyond 10.2.1 immediately to resolve the underlying deserialization flaw.
- Audit the WordPress environment for unused plugins or themes, as these may contain POP chains that could be leveraged by this vulnerability.
- Apply the principle of least privilege by reviewing user roles and stripping 'edit_course' capabilities from any accounts that do not strictly require them for course administration.
- Implement Web Application Firewall (WAF) rules to monitor for suspicious POST requests containing serialized PHP objects directed at lesson creation endpoints.
