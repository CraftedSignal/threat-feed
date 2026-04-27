---
title: Technostrobe HI-LED-WR120-G2 Improper Access Control Vulnerability (CVE-2026-5569)
slug: 2026-04-technostrobe-access-control
description: CVE-2026-5569 describes a remote improper access control vulnerability in the /Technostrobe/ endpoint of Technostrobe HI-LED-WR120-G2 5.5.0.1R6.03.30, potentially leading to unauthorized access and control of affected devices.
date: "2026-04-05T14:16:17Z"
severities:
  - high
tags:
  - cve-2026-5569
  - access-control
  - technostrobe
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5569
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5569
  - https://github.com/shiky8/my--cve-vulnerability-research/blob/main/my_VulnDB_cves/CVE-TECHNOSTROBE-01-BrokenAccessControl.md
  - https://vuldb.com/vuln/355339
rules:
  - title: Detect Technostrobe HI-LED-WR120-G2 Exploitation Attempt
    description: Detects attempts to exploit the CVE-2026-5569 vulnerability by monitoring requests to the /Technostrobe/ endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Technostrobe HI-LED-WR120-G2 Configuration Modification
    description: Detects POST requests to the /Technostrobe/ endpoint, which may indicate configuration modification attempts after exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-5569, affects Technostrobe HI-LED-WR120-G2 devices running firmware version 5.5.0.1R6.03.30. The vulnerability resides within the `/Technostrobe/` endpoint and stems from improper access control mechanisms. This flaw allows remote attackers to potentially bypass security restrictions and gain unauthorized access. The existence of a public exploit exacerbates the risk, making exploitation easier.  The vendor has been notified but has not provided a patch or…
