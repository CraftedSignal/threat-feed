---
title: Unauthenticated Privilege Escalation in Super Forms WordPress Plugin
slug: 2026-10-super-forms-priv-esc
description: An unauthenticated privilege escalation vulnerability (CVE-2026-15989) in the Super Forms WordPress plugin allows attackers to register administrative accounts via registration form injection.
date: "2026-10-01T08:39:24Z"
lastmod: "2026-10-03T00:54:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:wordpress:super_forms_drag_drop_form_builder:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=9F5189C5-CE21-56B0-BC4D-0E6C71AE4BEA&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - wordpress
  - privilege-escalation
  - cve-2026-15989
vendors:
  - WordPress
products:
  - Super Forms – Drag & Drop Form Builder (<= 6.3.316)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This makes it possible for unauthenticated attackers to register a new account with the Administrator role by injecting role=administrator into the data submitted to any published Super Forms registration form.
    confidence_band: high
cves:
  - id: CVE-2026-15989
    cvss: 9.8
    epss: 0.00294
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15989
  - https://sploitus.com/exploit?id=9F5189C5-CE21-56B0-BC4D-0E6C71AE4BEA&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-15989 Exploitation - Unauthorized Role Injection
    description: Detects exploitation attempts against the Super Forms plugin by identifying the injection of role parameters in HTTP POST requests to registration endpoints.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1078.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit user management logs for unexpected account creation since 2026-10-01
      owner: SOC
      due: 24h
      evidence: CVE-2026-15989 exploitation results in account creation
  mitigation_plan:
    - priority: immediate
      action: Upgrade Super Forms to version > 6.3.316 or disable Register & Login add-on
      owner: IT Operations
      addresses: CVE-2026-15989
      evidence: Plugin vulnerable up to and including 6.3.316
updates:
  - at: "2026-10-03T00:54:01Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=9F5189C5-CE21-56B0-BC4D-0E6C71AE4BEA&utm_source=rss&utm_medium=rss
---

The Super Forms - Drag & Drop Form Builder plugin for WordPress is affected by a critical privilege escalation vulnerability (CVE-2026-15989) in all versions up to and including 6.3.316. The flaw exists within the Register & Login add-on, specifically inside the before_email_success_msg() function. This function improperly handles client-submitted data by whitelisting the 'role' key and passing it directly into the user-data array processed by wp_insert_user(). 

Because the input is not validated against administrative settings, lacks an allow-list, and performs no capability checks via current_user_can(), unauthenticated attackers can inject the parameter 'role=administrator' into any public Super Forms registration form. This allows the creation of unauthorized accounts with full administrative privileges, granting the attacker complete control over the compromised WordPress instance. Defenders should identify all WordPress installations using Super Forms and ensure they are upgraded to a version beyond 6.3.316 or disable the Register & Login add-on immediately.

## Attack Chain

1. Attacker identifies a target WordPress site utilizing the Super Forms - Drag & Drop Form Builder plugin.
2. Attacker locates a public-facing registration form created with the Super Forms plugin.
3. Attacker initiates an HTTP POST request to the form handler, specifying register_login_action='register'.
4. Attacker injects the 'role=administrator' parameter into the registration form submission data.
5. The server-side before_email_success_msg() function in the Register & Login add-on accepts the malicious 'role' key without validation.
6. The system executes wp_insert_user() using the attacker-supplied role data.
7. A new user account is created with Administrator privileges.
8. Attacker authenticates with the newly created account to establish persistent administrative access.

## Impact

Successful exploitation allows unauthenticated attackers to gain full administrative access to affected WordPress installations. This leads to complete site compromise, including the ability to execute arbitrary code (via theme or plugin file uploads), exfiltrate sensitive user data, install backdoors, or redirect site traffic. This vulnerability carries a CVSS v3.1 base score of 9.8.

## Recommendation

1. Update the Super Forms - Drag & Drop Form Builder plugin to a version higher than 6.3.316 immediately.
2. If an update is unavailable, disable the Register & Login add-on to prevent exploitation of CVE-2026-15989.
3. Audit the user database for accounts with administrative privileges created unexpectedly after the publication of this advisory (October 1, 2026).
4. Deploy the provided webserver detection rule to monitor for suspicious registration attempts containing unexpected role parameters.
