---
title: Breeze Cache Plugin Arbitrary File Upload Vulnerability (CVE-2026-3844)
slug: 2026-04-breeze-cache-rce
description: The Breeze Cache plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation, potentially leading to remote code execution.
date: "2024-02-29T10:00:00Z"
severities:
  - critical
tags:
  - wordpress
  - plugin
  - file-upload
  - rce
vendors:
  - Cloudways
products:
  - Breeze Cache plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-3844
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3844
rules:
  - title: Detect Breeze Cache Arbitrary File Upload Attempt
    description: Detects attempts to exploit the Breeze Cache arbitrary file upload vulnerability by monitoring requests to fetch_gravatar_from_remote with suspicious file extensions in the query string.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Uploaded Files in Breeze Cache
    description: Detects attempts to access uploaded files in the wp-content/uploads/breeze/cache directory, which may indicate successful exploitation of the arbitrary file upload vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Breeze Cache plugin for WordPress, in versions up to and including 2.4.4, contains an arbitrary file upload vulnerability (CVE-2026-3844). This flaw stems from the lack of file type validation within the 'fetch_gravatar_from_remote' function. An unauthenticated attacker can exploit this vulnerability to upload arbitrary files to the affected WordPress site's server. Successful exploitation could lead to remote code execution on the server. It is important to note that the vulnerability can…
