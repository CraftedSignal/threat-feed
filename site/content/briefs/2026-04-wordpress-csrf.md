---
title: CSRF Vulnerability in WordPress Under Construction Plugin (CVE-2026-34896)
slug: 2026-04-wordpress-csrf
description: A cross-site request forgery (CSRF) vulnerability exists in the Analytify Under Construction, Coming Soon & Maintenance Mode WordPress plugin (versions n/a through 2.1.1), potentially allowing attackers to execute unauthorized actions on behalf of legitimate users.
date: "2026-04-07T09:16:21Z"
severities:
  - medium
tags:
  - wordpress
  - csrf
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-34896
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34896
  - https://patchstack.com/database/wordpress/plugin/under-construction-maintenance-mode/vulnerability/wordpress-under-construction-coming-soon-maintenance-mode-plugin-2-1-1-cross-site-request-forgery-csrf-vulnerability?_s_id=cve
rules:
  - title: Detect WordPress Plugin Setting Changes via POST
    description: Detects POST requests to wp-admin/options.php indicating a potential plugin setting change, possibly indicative of CSRF attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Plugin Installation via POST
    description: Detects POST requests to wp-admin/plugin-install.php potentially indicating unauthorized plugin installation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A cross-site request forgery (CSRF) vulnerability, identified as CVE-2026-34896, affects the Analytify Under Construction, Coming Soon & Maintenance Mode WordPress plugin. This vulnerability allows an attacker to trick a user into performing actions they did not intend to, such as modifying plugin settings or performing administrative tasks, provided the targeted user is authenticated to the WordPress site. The vulnerability exists in versions from n/a through 2.1.1. The vulnerability was…
