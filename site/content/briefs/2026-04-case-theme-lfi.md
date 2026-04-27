---
title: Case Theme User WordPress Plugin Local File Inclusion Vulnerability (CVE-2025-5804)
slug: 2026-04-case-theme-lfi
description: CVE-2025-5804 is a PHP Local File Inclusion vulnerability in the Case Theme User WordPress plugin before version 1.0.4 due to improper filename control in include/require statements, potentially allowing attackers to execute arbitrary code by including malicious local files.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - php
  - lfi
  - wordpress
  - cve-2025-5804
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-5804
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-5804
  - https://patchstack.com/database/wordpress/plugin/case-theme-user/vulnerability/wordpress-case-theme-user-1-0-4-local-file-inclusion-vulnerability?_s_id=cve
ioc_counts:
  email: 1
rules:
  - title: Detect Case Theme User LFI Attempt
    description: Detects potential Local File Inclusion (LFI) attempts targeting the Case Theme User WordPress plugin by monitoring HTTP requests containing directory traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect PHP file access outside webroot
    description: Detects potential Local File Inclusion (LFI) attempts by monitoring PHP file access outside the webroot.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A local file inclusion (LFI) vulnerability, identified as CVE-2025-5804, affects the Case Theme User WordPress plugin before version 1.0.4. The vulnerability stems from insufficient validation of filenames passed to PHP's `include` or `require` statements. This allows an unauthenticated attacker to potentially include arbitrary local files on the server hosting the WordPress instance. Successful exploitation could lead to sensitive information disclosure, arbitrary code execution, or denial of…
