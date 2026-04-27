---
title: Gravity SMTP Plugin Missing Authorization Vulnerability (CVE-2026-4162)
slug: 2026-04-gravity-smtp-auth-bypass
description: The Gravity SMTP plugin for WordPress is vulnerable to Missing Authorization, allowing authenticated attackers with subscriber-level access or higher to uninstall/deactivate the plugin and delete plugin options, and is also exploitable via Cross-Site Request Forgery.
date: "2026-04-10T10:16:04Z"
severities:
  - medium
tags:
  - wordpress
  - missing-authorization
  - plugin
  - cve-2026-4162
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-4162
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4162
  - https://www.gravityforms.com/brand-new-release-gravity-smtp-2-1-5/
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/0f9d18a4-262b-4011-91e9-b29a27a76470?source=cve
rules:
  - title: Detect WordPress Plugin Uninstall via Missing Auth
    description: Detects attempts to uninstall a WordPress plugin via a missing authorization vulnerability. This rule identifies HTTP requests targeting the plugin management endpoint with the 'action=uninstall-plugin' parameter.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Plugin Options Deletion
    description: Detects attempts to delete WordPress plugin options, which can be indicative of exploitation attempts following a missing authorization vulnerability.
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

The Gravity SMTP plugin, a WordPress extension facilitating email sending through SMTP, contains a missing authorization vulnerability (CVE-2026-4162) affecting versions 2.1.4 and earlier. This flaw allows authenticated users with minimal subscriber-level permissions to perform administrative actions such as uninstalling and deactivating the plugin, as well as deleting its associated options. The vulnerability stems from the plugin failing to properly validate user authorization before…
