---
title: Fluent Forms Plugin Authorization Bypass via User-Controlled Key (CVE-2026-5396)
slug: 2026-05-fluent-forms-auth-bypass
description: The Fluent Forms plugin for WordPress is vulnerable to authorization bypass via a user-controlled key (CVE-2026-5396), allowing authenticated attackers with restricted access to specific forms to manipulate submissions of unauthorized forms by spoofing the 'form_id' parameter.
date: "2026-05-14T06:17:56Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - authorization-bypass
  - wordpress
  - plugin
vendors:
  - WordPress
products:
  - Fluent Forms plugin <= 6.1.21
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-5396
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5396
  - CVE-2026-5396
rules:
  - title: Detect Fluent Forms Authorization Bypass via form_id Parameter
    description: Detects CVE-2026-5396 exploitation — an authorization bypass vulnerability in the Fluent Forms plugin where the form_id parameter is manipulated.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect Fluent Forms Unauthorized Form Submission Access
    description: Detects unauthorized access to Fluent Forms submissions based on unusual user agent and form_id manipulation
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

The Fluent Forms plugin for WordPress, versions up to and including 6.1.21, is susceptible to an authorization bypass vulnerability (CVE-2026-5396). This flaw arises from the `SubmissionPolicy` class's reliance on a user-supplied `form_id` query parameter to authorize submission-level actions, including reading, modifying, deleting, and adding notes. An authenticated attacker, granted Fluent Forms Manager access solely to specific forms, can exploit this vulnerability. By manipulating the `form_id` parameter to resemble a form they are authorized for, they can gain unauthorized access to, and control over, form submissions of other, restricted forms. This impacts the confidentiality and integrity of data collected through Fluent Forms.

## Attack Chain

1. Attacker authenticates to WordPress with an account that has Fluent Forms Manager access, restricted to specific forms.
2. Attacker identifies the 'form_id' of a form they are authorized to manage.
3. Attacker crafts a malicious HTTP request targeting a Fluent Forms endpoint that handles submission-level actions (e.g., reading, modifying, deleting, adding notes).
4. The malicious request includes the 'form_id' parameter, spoofed to match the 'form_id' of a form they are authorized to manage.
5. The request is sent to the WordPress server hosting the vulnerable Fluent Forms plugin.
6. The `SubmissionPolicy` class in Fluent Forms incorrectly authorizes the request based on the spoofed 'form_id' parameter.
7. Attacker gains unauthorized access to form submissions associated with the target 'form_id'.
8. The attacker can then perform actions such as reading, modifying the status, adding notes to, or permanently deleting the form submissions.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass authorization controls within the Fluent Forms plugin. This can lead to unauthorized access and manipulation of sensitive form submission data. An attacker with limited access can read, modify, or delete submissions from other forms, potentially impacting data integrity and confidentiality. The vulnerability affects all users of the Fluent Forms plugin up to version 6.1.21.

## Recommendation

*   Upgrade the Fluent Forms plugin to the latest version to patch CVE-2026-5396.
*   Deploy the Sigma rule "Detect Fluent Forms Authorization Bypass via form_id Parameter" to your SIEM to identify potential exploitation attempts in web server logs.
*   Review user roles and permissions within Fluent Forms to ensure least privilege is enforced.
*   Monitor web server logs for suspicious requests containing manipulated `form_id` parameters as described in the Attack Chain.
