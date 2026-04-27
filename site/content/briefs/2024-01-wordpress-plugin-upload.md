---
title: WordPress Drag and Drop File Upload Plugin Vulnerable to Arbitrary File Upload (CVE-2026-5364)
slug: 2024-01-wordpress-plugin-upload
description: The Drag and Drop File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file upload in versions up to 1.1.3, allowing unauthenticated attackers to upload arbitrary PHP files by manipulating the file type parameter and exploiting extension sanitization vulnerabilities.
date: "2024-01-03T18:23:00Z"
severities:
  - high
tags:
  - wordpress
  - file-upload
  - rce
  - plugin
  - CVE-2026-5364
vendors:
  - WordPress
products:
  - Drag and Drop File Upload for Contact Form 7 plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-5364
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5364
rules:
  - title: Detect Suspicious File Upload via Drag and Drop CF7
    description: Detects potential exploitation of the Drag and Drop File Upload for Contact Form 7 plugin vulnerability (CVE-2026-5364) by monitoring for suspicious file extensions in HTTP POST requests to the plugin's upload endpoint.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-5364
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Upload via Drag and Drop CF7 - UNC Path
    description: Detects potential exploitation of the Drag and Drop File Upload for Contact Form 7 plugin vulnerability (CVE-2026-5364) by monitoring for suspicious file extensions in HTTP POST requests to the plugin's upload endpoint. Looks for UNC paths which are also an indicator of suspicious activity
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-5364
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Drag and Drop File Upload for Contact Form 7 plugin for WordPress, in versions up to and including 1.1.3, contains an arbitrary file upload vulnerability tracked as CVE-2026-5364. The flaw stems from insufficient sanitization of file extensions during the upload process. Specifically, the plugin extracts the file extension before sanitization and allows the file type parameter to be controlled by the attacker. Furthermore, validation occurs on the unsanitized extension, while the file is…
