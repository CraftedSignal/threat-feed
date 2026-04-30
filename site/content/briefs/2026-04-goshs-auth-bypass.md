---
title: goshs Authentication Bypass Vulnerability (CVE-2026-34581)
slug: 2026-04-goshs-auth-bypass
description: goshs versions 1.1.0 to before 2.0.0-beta.2 are vulnerable to authentication bypass via Share Token, potentially allowing code execution (CVE-2026-34581).
date: "2026-04-02T19:21:32Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-34581
  - authentication-bypass
  - code-execution
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34581
  - https://github.com/patrickhener/goshs/commit/6fb224ed15c2ccc0c61a5ebe22f2401eb06e9216
  - https://github.com/patrickhener/goshs/releases/tag/v2.0.0-beta.2
  - https://github.com/patrickhener/goshs/security/advisories/GHSA-jgfx-74g2-9r6g
rules:
  - title: Detect Goshs Code Execution via Auth Bypass
    description: Detects potential attempts to exploit the authentication bypass vulnerability in goshs leading to code execution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 1
---

CVE-2026-34581 affects goshs, a SimpleHTTPServer written in Go. Versions 1.1.0 to before 2.0.0-beta.2 are susceptible to an authentication bypass vulnerability. When a user attempts to access the server with a Share Token, it is possible to bypass the intended file download restriction, gaining access to all goshs functionalities. This includes the ability to execute arbitrary code on the server. The vulnerability was patched in version 2.0.0-beta.2. This vulnerability allows unauthenticated attackers to potentially gain full control of the server hosting goshs. Organizations using affected versions of goshs should upgrade immediately.

## Attack Chain

1.  Attacker identifies a server running a vulnerable version of goshs (1.1.0 to before 2.0.0-beta.2).
2.  Attacker requests a resource that should be protected by the Share Token.
3.  The server prompts for the Share Token.
4.  Attacker exploits the authentication bypass vulnerability by manipulating the request (details not specified in source).
5.  Successful exploitation grants the attacker access to all goshs functionalities, bypassing the intended file download restriction.
6.  Attacker leverages the unrestricted access to execute arbitrary code on the server.
7.  Attacker gains a shell or other form of remote access to the compromised server.

## Impact

Successful exploitation of CVE-2026-34581 allows an unauthenticated attacker to execute arbitrary code on the server. This can lead to complete system compromise, data theft, or denial of service. The impact is significant for organizations using vulnerable versions of goshs to serve sensitive files or applications. The report does not mention the number of victims, but the severity is high given the potential for code execution.

## Recommendation

*   Upgrade goshs to version 2.0.0-beta.2 or later to patch CVE-2026-34581 (reference: https://github.com/patrickhener/goshs/releases/tag/v2.0.0-beta.2).
*   Deploy the Sigma rule `Detect Goshs Code Execution via Auth Bypass` to detect potential exploitation attempts.
*   Monitor web server logs for suspicious activity related to goshs, specifically requests that might be attempting to bypass authentication.
