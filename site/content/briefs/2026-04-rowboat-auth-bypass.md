---
title: Rowboatlabs Rowboat Improper Authentication Vulnerability (CVE-2026-6635)
slug: 2026-04-rowboat-auth-bypass
description: An improper authentication vulnerability in rowboatlabs rowboat <=0.1.67 allows remote attackers to bypass authentication by manipulating the X-Tools-JWE argument in the tool_call function, potentially leading to unauthorized access and control.
date: "2026-04-20T12:16:09Z"
type: advisory
types:
  - advisory
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

A critical security flaw, identified as CVE-2026-6635, has been discovered in rowboatlabs rowboat, specifically in versions up to and including 0.1.67. This vulnerability resides within the `tool_call` function located in the `apps/experimental/tools_webhook/app.py` file of the `tools_webhook` component.  The vulnerability stems from the improper handling of the `X-Tools-JWE` argument, which can be manipulated by a remote attacker to bypass authentication mechanisms. This flaw allows attackers to potentially gain unauthorized access and execute arbitrary actions within the application. Public exploits are available, increasing the urgency for mitigation. The vendor was notified but has not responded.

## Attack Chain

1.  Attacker identifies a vulnerable instance of rowboatlabs rowboat version 0.1.67 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the `tool_call` function.
3.  Within the HTTP request, the attacker manipulates the `X-Tools-JWE` argument with a crafted payload designed to bypass authentication checks.
4.  The vulnerable `tool_call` function fails to properly validate the manipulated `X-Tools-JWE` argument.
5.  The application grants the attacker unauthorized access based on the bypassed authentication.
6.  The attacker leverages the unauthorized access to execute actions normally restricted to authenticated users.
7.  Depending on the application's functionality, this could involve data exfiltration, modification, or execution of arbitrary code.

## Impact

Successful exploitation of CVE-2026-6635 can lead to complete compromise of the rowboatlabs rowboat application. Attackers can gain unauthorized access to sensitive data, modify application settings, or even execute arbitrary code on the server. Due to the ease of exploitation with public exploits available, all instances of vulnerable rowboat versions are at immediate risk. The specific impact depends on the application's role and the data it handles, but potential consequences include data breaches, service disruption, and financial loss.

## Recommendation

*   Apply appropriate input validation to `X-Tools-JWE` argument using `tool_call` function within `apps/experimental/tools_webhook/app.py` to prevent improper authentication (CVE-2026-6635).
*   Deploy the Sigma rule `Detect Rowboat Authentication Bypass Attempt via X-Tools-JWE Manipulation` to detect exploitation attempts.
*   Monitor web server logs for HTTP requests targeting the `tool_call` function with unusual `X-Tools-JWE` values.
