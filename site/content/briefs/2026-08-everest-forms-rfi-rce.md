---
title: Everest Forms Plugin Arbitrary File Read and Deletion Vulnerability
slug: 2026-08-everest-forms-rfi-rce
description: The Everest Forms plugin for WordPress is vulnerable to arbitrary file read and deletion, allowing unauthenticated attackers to access sensitive data or cause denial of service by manipulating the 'old_files' parameter in versions up to 3.4.4.
date: "2026-04-20T20:35:20Z"
severities:
  - critical
tags:
  - wordpress
  - plugin
  - file-read
  - file-deletion
  - cve-2026-5478
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-5478
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5478
rules:
  - title: Detect Everest Forms Arbitrary File Read Attempt
    description: Detects attempts to exploit the Everest Forms plugin vulnerability (CVE-2026-5478) by identifying path traversal sequences in HTTP POST requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Deletion by Web Server User
    description: Detects potential exploitation of CVE-2026-5478 by monitoring file deletion events performed by the web server user, focusing on sensitive files.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The Everest Forms plugin for WordPress, versions 3.4.4 and earlier, contains an arbitrary file read and deletion vulnerability (CVE-2026-5478). This flaw stems from the plugin's improper handling of the `old_files` parameter within form submissions. Specifically, the plugin trusts attacker-controlled data as legitimate server-side upload state and insecurely converts URLs into local filesystem paths without adequate sanitization. This lack of input validation enables unauthenticated attackers…
