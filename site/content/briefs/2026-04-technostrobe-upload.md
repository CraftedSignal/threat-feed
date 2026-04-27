---
title: Technostrobe HI-LED-WR120-G2 Unrestricted File Upload Vulnerability (CVE-2026-5573)
slug: 2026-04-technostrobe-upload
description: CVE-2026-5573 allows remote attackers to perform unrestricted file uploads on Technostrobe HI-LED-WR120-G2 devices by manipulating the 'cwd' argument when interacting with the /fs file.
date: "2026-04-05T15:16:41Z"
severities:
  - high
tags:
  - CVE-2026-5573
  - file-upload
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5573
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5573
  - https://github.com/shiky8/my--cve-vulnerability-research/blob/main/my_VulnDB_cves/CVE-TECHNOSTROBE-05-FileUpload.md
  - https://vuldb.com/submit/783326
  - https://vuldb.com/vuln/355343
  - https://vuldb.com/vuln/355343/cti
ioc_counts:
  url: 4
rules:
  - title: Detect Suspicious cwd Parameter Manipulation in /fs Endpoint
    description: Detects attempts to manipulate the `cwd` parameter in requests to the `/fs` endpoint, potentially indicating an exploitation attempt for CVE-2026-5573.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Upload of Common Web Shells
    description: Detects the upload of common web shell file extensions to the /fs endpoint.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-5573, has been identified in Technostrobe HI-LED-WR120-G2 version 5.5.0.1R6.03.30. This flaw allows unauthenticated, remote attackers to upload arbitrary files to the device due to improper handling of the 'cwd' argument when accessing the `/fs` file. Publicly available exploits exist, increasing the risk of widespread exploitation. The vendor was notified but did not respond. This vulnerability poses a significant threat due to the potential for complete…
