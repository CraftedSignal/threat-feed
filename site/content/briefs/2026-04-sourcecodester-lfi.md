---
title: SourceCodester Leave Application System 1.0 File Inclusion Vulnerability (CVE-2026-5210)
slug: 2026-04-sourcecodester-lfi
description: SourceCodester Leave Application System 1.0 is vulnerable to remote file inclusion (CVE-2026-5210) due to improper handling of the 'page' argument, potentially allowing attackers to execute arbitrary code.
date: "2026-03-31T19:16:29Z"
severities:
  - high
tags:
  - cve-2026-5210
  - file-inclusion
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5210
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5210
  - https://medium.com/@hemantrajbhati5555/local-file-inclusion-lfi-in-leave-application-system-php-sqlite3-4e095bb7ee40
  - https://vuldb.com/submit/780419
  - https://vuldb.com/vuln/354346
  - https://vuldb.com/vuln/354346/cti
  - https://www.sourcecodester.com/
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect LFI Attempts via Page Parameter
    description: Detects attempts to exploit LFI vulnerabilities by analyzing the 'page' parameter in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect access to sensitive files via web server
    description: Detects access to common sensitive files via web requests that may indicate LFI or other vulnerability
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SourceCodester Leave Application System version 1.0 is vulnerable to a file inclusion vulnerability (CVE-2026-5210). This vulnerability allows a remote attacker to include arbitrary files on the server by manipulating the `page` argument in a request.  The vulnerability exists because the application fails to properly sanitize user-supplied input, leading to the inclusion of potentially malicious files. Public exploits are available, increasing the risk of exploitation. This vulnerability poses…
