---
title: Contest Gallery WordPress Plugin Authentication Bypass Vulnerability (CVE-2026-4021)
slug: 2026-03-contest-gallery-auth-bypass
description: CVE-2026-4021 describes an authentication bypass vulnerability in the Contest Gallery plugin for WordPress, allowing unauthenticated attackers to gain admin access by manipulating the user activation key and using an AJAX login endpoint.
date: "2026-03-24T00:16:31Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - wordpress
  - authentication-bypass
  - plugin-vulnerability
  - cve-2026-4021
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.004
    technique_name: 'Boot or Logon Autostart Execution: WMI Event Subscription'
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4021
ioc_counts:
  email: 1
rules:
  - title: Detect Contest Gallery Authentication Bypass Attempt via AJAX
    description: Detects attempts to exploit CVE-2026-4021 by monitoring for suspicious POST requests to the WordPress AJAX endpoint with the 'post_cg1l_login_user_by_key' action.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect User Registration with Crafted Email for Activation Key Overwrite
    description: Detects user registration attempts using crafted email addresses designed to overwrite the admin's activation key in the database via CVE-2026-4021.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Contest Gallery plugin for WordPress, versions up to and including 28.1.5, is vulnerable to a critical authentication bypass (CVE-2026-4021). This vulnerability stems from how the `users-registry-check-after-email-or-pin-confirmation.php` script handles email confirmations, combined with an unauthenticated key-based login endpoint in `ajax-functions-frontend.php`.  If the `RegMailOptional=1` setting is enabled (non-default), an attacker can register a new user account with a specially…
