---
title: WP Customer Area Plugin Arbitrary File Read and Deletion Vulnerability
slug: 2026-04-wp-customer-area-file-read-delete
description: The WP Customer Area plugin for WordPress is vulnerable to arbitrary file read and deletion due to insufficient file path validation, allowing authenticated attackers to read sensitive files or delete critical files leading to potential remote code execution.
date: "2026-04-17T17:17:07Z"
severities:
  - critical
tags:
  - wordpress
  - plugin
  - file-read
  - file-deletion
  - rce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-3464
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3464
rules:
  - title: Detect WP Customer Area Arbitrary File Access Attempt
    description: Detects attempts to exploit CVE-2026-3464 by identifying suspicious file paths in requests to the 'ajax_attach_file' function.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WP Customer Area Arbitrary File Deletion Attempt
    description: Detects attempts to exploit CVE-2026-3464 by identifying suspicious file paths in requests to the 'ajax_attach_file' function, specifically looking for deletion attempts.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The WP Customer Area plugin, a popular WordPress plugin, is susceptible to an arbitrary file read and deletion vulnerability. This flaw, identified as CVE-2026-3464, resides within the 'ajax_attach_file' function and stems from inadequate file path validation. All versions of the plugin up to and including 8.3.4 are affected. The vulnerability enables authenticated attackers with minimal privileges (e.g., Subscriber), granted access by an administrator, to read arbitrary files on the server…
