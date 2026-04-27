---
title: Riaxe Product Customizer WordPress Plugin Privilege Escalation Vulnerability (CVE-2026-3596)
slug: 2026-04-wordpress-privesc
description: The Riaxe Product Customizer plugin for WordPress is vulnerable to privilege escalation, allowing unauthenticated attackers to update arbitrary WordPress options via a publicly accessible AJAX endpoint and escalate privileges to administrator.
date: "2026-04-16T06:16:15Z"
severities:
  - critical
tags:
  - wordpress
  - privilege-escalation
  - cve-2026-3596
  - plugin
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-3596
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3596
rules:
  - title: Detect Riaxe Product Customizer Privilege Escalation Attempt
    description: Detects attempts to exploit the privilege escalation vulnerability (CVE-2026-3596) in the Riaxe Product Customizer plugin by monitoring POST requests to admin-ajax.php with the install-imprint action.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1548.001
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized User Registration After CVE-2026-3596 Exploitation
    description: Detects potentially unauthorized user registration events following exploitation of the Riaxe Product Customizer vulnerability. This assumes that attackers will enable user registration to create an admin account.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1548.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Riaxe Product Customizer plugin for WordPress, versions 2.1.2 and earlier, contains a critical privilege escalation vulnerability (CVE-2026-3596). This flaw stems from an unauthenticated AJAX action, 'wp_ajax_nopriv_install-imprint', which is improperly secured. The corresponding function, `ink_pd_add_option()`, allows unauthenticated users to modify arbitrary WordPress options by sending POST requests. There are no nonce checks, capability checks, or input validation performed on the…
