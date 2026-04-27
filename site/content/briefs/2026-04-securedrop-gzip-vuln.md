---
title: SecureDrop Client Code Execution via Gzip Extraction Vulnerability
slug: 2026-04-securedrop-gzip-vuln
description: A compromised SecureDrop server can achieve code execution on the SecureDrop client's virtual machine by exploiting improper filename validation during gzip archive extraction, allowing for the overwriting of critical files.
date: "2026-04-18T01:16:18Z"
severities:
  - high
tags:
  - securedrop
  - gzip
  - code execution
  - vulnerability
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Malicious File
cves:
  - id: CVE-2026-35465
    cvss: 7.5
  - id: CVE-2025-24888
    cvss: 8.1
    epss: 0.0307
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35465
rules:
  - title: Detect SecureDrop Client File Overwrite Attempt
    description: Detects attempts to overwrite critical files within the SecureDrop Client installation directory, potentially indicating exploitation of CVE-2026-35465.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1202
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Process Accessing SecureDrop SQLite Database
    description: Detects processes other than the SecureDrop client accessing the SQLite database, which might indicate unauthorized access after a successful exploit.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

SecureDrop Client, a desktop application designed for secure communication between journalists and sources, is vulnerable to code execution (versions 0.17.4 and below). The vulnerability, identified as CVE-2026-35465, stems from improper filename validation during the extraction of gzip archives. A compromised SecureDrop Server can leverage this flaw to overwrite critical files, such as the SQLite database, on the Client's virtual machine (sd-app). While exploiting this vulnerability requires…
