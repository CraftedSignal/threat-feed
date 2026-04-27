---
title: IBM Tivoli Netcool Impact Sensitive Information Leak via Log Files (CVE-2026-4788)
slug: 2026-04-tivoli-log-leak
description: IBM Tivoli Netcool Impact 7.1.0.0 through 7.1.0.37 stores sensitive information in log files, potentially exposing it to unauthorized local users, tracked as CVE-2026-4788.
date: "2026-04-08T01:16:41Z"
severities:
  - medium
tags:
  - cve-2026-4788
  - information-disclosure
  - log-files
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data from Local System
cves:
  - id: CVE-2026-4788
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4788
  - https://www.ibm.com/support/pages/node/7268267
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Access to Tivoli Netcool Impact Log Files
    description: Detects suspicious processes attempting to read Tivoli Netcool Impact log files, indicating potential exploitation of CVE-2026-4788
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1005
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Access to Tivoli Netcool Impact Log Files (Linux)
    description: Detects suspicious processes attempting to read Tivoli Netcool Impact log files on Linux systems, indicating potential exploitation of CVE-2026-4788
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1005
    data_sources:
      - file_event
      - linux
rules_count: 2
---

IBM Tivoli Netcool Impact versions 7.1.0.0 through 7.1.0.37 are vulnerable to sensitive information disclosure. Specifically, the application stores sensitive data within its log files. A local attacker with access to the file system where these logs are stored could potentially read this information. This vulnerability is identified as CVE-2026-4788, with a CVSS v3.1 score of 8.4, indicating a high severity. This issue affects organizations utilizing vulnerable versions of IBM Tivoli Netcool…
