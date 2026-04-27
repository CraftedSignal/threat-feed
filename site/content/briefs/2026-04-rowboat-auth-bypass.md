---
title: Rowboatlabs Rowboat Improper Authentication Vulnerability (CVE-2026-6635)
slug: 2026-04-rowboat-auth-bypass
description: An improper authentication vulnerability in rowboatlabs rowboat <=0.1.67 allows remote attackers to bypass authentication by manipulating the X-Tools-JWE argument in the tool_call function, potentially leading to unauthorized access and control.
date: "2026-04-20T12:16:09Z"
severities:
  - high
tags:
  - cve-2026-6635
  - authentication bypass
  - web application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6635
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6635
  - https://github.com/Dave-gilmore-aus/security-advisories/blob/main/rowbat-advisory
  - https://vuldb.com/vuln/358269
rules:
  - title: Detect Rowboat Authentication Bypass Attempt via X-Tools-JWE Manipulation
    description: Detects attempts to exploit CVE-2026-6635 by manipulating the X-Tools-JWE header in requests to the tool_call endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
      - linux
  - title: Detect Rowboat tools_webhook Access Attempt
    description: Detects access to the tools_webhook component in Rowboat, which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security flaw, identified as CVE-2026-6635, has been discovered in rowboatlabs rowboat, specifically in versions up to and including 0.1.67. This vulnerability resides within the `tool_call` function located in the `apps/experimental/tools_webhook/app.py` file of the `tools_webhook` component.  The vulnerability stems from the improper handling of the `X-Tools-JWE` argument, which can be manipulated by a remote attacker to bypass authentication mechanisms. This flaw allows attackers…
