---
title: AcyMailing Plugin Privilege Escalation Vulnerability (CVE-2026-3614)
slug: 2026-04-acymailing-privesc
description: The AcyMailing plugin for WordPress is vulnerable to privilege escalation (CVE-2026-3614), allowing authenticated attackers with subscriber-level access to gain administrative privileges.
date: "2026-04-16T06:16:18Z"
severities:
  - critical
tags:
  - wordpress
  - privilege-escalation
  - acymailing
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-3614
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3614
rules:
  - title: AcyMailing Unauthorized AJAX Access Attempt
    description: Detects attempts to access the acymailing_router AJAX handler without administrator privileges, indicating a potential privilege escalation attempt (CVE-2026-3614).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1212
    data_sources:
      - webserver
      - linux
  - title: AcyMailing Autologin Enabled
    description: Detects when the autologin feature is enabled in AcyMailing, which is a prerequisite for exploiting CVE-2026-3614. Requires AcyMailing logging.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1212
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The AcyMailing plugin for WordPress, a popular email marketing tool, contains a critical privilege escalation vulnerability, tracked as CVE-2026-3614. Affecting versions 9.11.0 through 10.8.1, the vulnerability stems from a missing capability check on the `wp_ajax_acymailing_router` AJAX handler. This oversight allows authenticated attackers with minimal privileges (Subscriber level or higher) to bypass access controls intended to restrict access to administrative functions. Successful…
