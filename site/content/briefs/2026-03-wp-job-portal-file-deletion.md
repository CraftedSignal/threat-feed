---
title: WP Job Portal Plugin Arbitrary File Deletion Vulnerability (CVE-2026-4758)
slug: 2026-03-wp-job-portal-file-deletion
description: The WP Job Portal plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation, allowing authenticated attackers with subscriber-level access or higher to delete arbitrary files, potentially leading to remote code execution.
date: "2026-03-26T00:16:41Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve
  - wordpress
  - file-deletion
  - remote-code-execution
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4758
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/e96f31e0-4b2e-4ea1-a3e5-fd7452a2fea9?source=cve
rules:
  - title: Detect WP Job Portal Arbitrary File Deletion Attempt
    description: Detects attempts to exploit CVE-2026-4758 by monitoring for suspicious requests to the 'removeFileCustom' function in the WP Job Portal plugin.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect wp-config.php Deletion via Web Server Logs
    description: Detects attempts to delete the wp-config.php file by monitoring for corresponding web server log entries.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The WP Job Portal plugin for WordPress versions up to and including 2.4.9 is susceptible to an arbitrary file deletion vulnerability (CVE-2026-4758). The vulnerability stems from insufficient file path validation within the `WPJOBPORTALcustomfields::removeFileCustom` function. Authenticated attackers with Subscriber-level access or higher can exploit this flaw to delete arbitrary files on the server. Successful exploitation allows attackers to delete critical files such as `wp-config.php`…
