---
title: ChatGPTNextWeb NextChat Improper Authorization Vulnerability (CVE-2026-7644)
slug: 2024-01-nextchat-auth-bypass
description: CVE-2026-7644 is an improper authorization vulnerability in the addMcpServer function of ChatGPTNextWeb NextChat version 2.16.1 and earlier, allowing for potential remote exploitation following public disclosure of the exploit.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - authorization
  - cve-2026-7644
  - web-application
vendors:
  - ChatGPTNextWeb
products:
  - NextChat (<= 2.16.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Shared Network Drive
cves:
  - id: CVE-2026-7644
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7644
rules:
  - title: Detect Unauthorized addMcpServer Access
    description: Detects potential unauthorized access to the addMcpServer function in NextChat, indicating a possible exploit of CVE-2026-7644.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 1
---

A vulnerability, CVE-2026-7644, affects ChatGPTNextWeb NextChat up to version 2.16.1. The flaw exists within the `addMcpServer` function located in the `app/mcp/actions.ts` file. This vulnerability allows for improper authorization, potentially enabling unauthorized actions. The exploit has been publicly disclosed, increasing the risk of exploitation. The vendor was notified, but there has been no response as of the time of this writing. This vulnerability allows for remote exploitation, meaning an attacker does not need local access to the system to exploit it. Defenders should prioritize patching or mitigating this vulnerability to prevent unauthorized access and potential data breaches.

## Attack Chain

1.  Attacker identifies a ChatGPTNextWeb NextChat instance running version 2.16.1 or earlier.
2.  Attacker sends a crafted request to the `addMcpServer` function in `app/mcp/actions.ts`.
3.  The application fails to properly authorize the request due to the vulnerability in `addMcpServer`.
4.  The attacker bypasses authorization checks.
5.  The attacker successfully adds a malicious MCP server configuration.
6.  The application uses the malicious MCP server configuration, potentially leading to further unauthorized actions.
7.  Attacker gains unauthorized access to sensitive data or functionality.

## Impact

Successful exploitation of CVE-2026-7644 could lead to unauthorized access to a NextChat instance. An attacker could potentially manipulate MCP server configurations, leading to further compromise of the application and associated data. Since the exploit is publicly available, the risk of exploitation is significantly elevated, potentially affecting all unpatched instances of NextChat version 2.16.1 or earlier.

## Recommendation

*   Upgrade ChatGPTNextWeb NextChat to a version higher than 2.16.1 to patch CVE-2026-7644.
*   Monitor web server logs for suspicious requests targeting the `addMcpServer` function in `app/mcp/actions.ts`.
*   Deploy the Sigma rule to detect unauthorized calls to the `addMcpServer` function.
