---
title: ProfilePress WordPress Plugin Membership Payment Bypass Vulnerability
slug: 2026-04-profilepress-bypass
description: The ProfilePress WordPress plugin before 4.16.12 is vulnerable to an unauthorized membership payment bypass, allowing authenticated attackers to obtain paid memberships without payment by manipulating subscription IDs during checkout.
date: "2026-04-04T09:16:20Z"
severities:
  - high
tags:
  - wordpress
  - plugin
  - vulnerability
  - membership
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-3445
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3445
rules:
  - title: Detect ProfilePress Membership Bypass Attempt
    description: Detects attempts to exploit the ProfilePress membership bypass vulnerability by monitoring for POST requests to admin-ajax.php with the ppress_process_checkout action.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect ProfilePress Membership Bypass Attempt - change_plan_sub_id Parameter
    description: Detects attempts to exploit the ProfilePress membership bypass vulnerability by monitoring for POST requests to admin-ajax.php with the ppress_process_checkout action and the presence of change_plan_sub_id in the query string.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The ProfilePress plugin for WordPress, specifically the "Paid Membership Plugin, Ecommerce, User Registration Form, Login Form, User Profile & Restrict Content" version 4.16.11 and earlier, contains a vulnerability (CVE-2026-3445) that allows authenticated attackers to bypass membership payment requirements. This flaw stems from a missing ownership verification on the `change_plan_sub_id` parameter within the `process_checkout()` function. An attacker with subscriber-level access can exploit…
