---
title: Technostrobe HI-LED-WR120-G2 Improper Authentication Vulnerability (CVE-2026-5570)
slug: 2026-04-technostrobe-auth-bypass
description: CVE-2026-5570 is an improper authentication vulnerability in the index_config function of the /LoginCB file of Technostrobe HI-LED-WR120-G2 version 5.5.0.1R6.03.30, allowing remote attackers to bypass authentication.
date: "2026-04-05T14:16:17Z"
severities:
  - high
tags:
  - cve
  - authentication-bypass
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-5570
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5570
  - https://github.com/shiky8/my--cve-vulnerability-research/blob/main/my_VulnDB_cves/CVE-TECHNOSTROBE-02-AuthBypass.md
  - https://vuldb.com/vuln/355340
rules:
  - title: Detect Access to Vulnerable LoginCB Endpoint
    description: Detects HTTP requests to the /LoginCB endpoint, which may indicate exploitation attempts against CVE-2026-5570.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect POST Requests to Vulnerable LoginCB Endpoint
    description: Detects HTTP POST requests to the /LoginCB endpoint, which may indicate exploitation attempts against CVE-2026-5570.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-5570, exists in Technostrobe HI-LED-WR120-G2 version 5.5.0.1R6.03.30. This vulnerability resides within the `index_config` function of the `/LoginCB` file. Successful exploitation allows remote attackers to bypass authentication mechanisms. Publicly available exploit code exists, increasing the risk of widespread exploitation. The vendor was notified but did not respond. Given the lack of vendor response and the existence of a public exploit, organizations…
