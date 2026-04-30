---
title: SmythOS sre Authentication Bypass Vulnerability (CVE-2026-7022)
slug: 2026-04-smythos-auth-bypass
description: A remote improper authentication vulnerability exists in SmythOS sre up to version 0.0.15, allowing attackers to bypass authentication by manipulating the X-DEBUG-RUN/X-DEBUG-INJ arguments in the HTTP Header Handler component.
date: "2026-04-26T06:16:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - CVE-2026-7022
products:
  - sre
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7022
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7022
rules:
  - title: Detect SmythOS Authentication Bypass Attempt via X-DEBUG Headers
    description: Detects attempts to exploit CVE-2026-7022 by looking for HTTP requests with specific X-DEBUG-RUN or X-DEBUG-INJ headers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SmythOS Authentication Bypass Attempt via HTTP Headers
    description: Detects authentication bypass attempts by identifying abnormal HTTP header usage.
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

A security vulnerability, CVE-2026-7022, has been identified in SmythOS sre versions up to 0.0.15. The vulnerability resides in the AgentRuntime function within the packages/core/src/subsystems/AgentManager/AgentRuntime.class.ts file, specifically affecting the HTTP Header Handler. By manipulating the X-DEBUG-RUN and X-DEBUG-INJ arguments within HTTP headers, an attacker can bypass authentication mechanisms. This vulnerability is remotely exploitable and has a publicly available exploit, posing a significant risk to systems running vulnerable versions of SmythOS sre. The vendor was notified but did not respond.

## Attack Chain

1.  The attacker identifies a SmythOS sre instance running version 0.0.15 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the AgentRuntime function.
3.  The attacker includes specially crafted X-DEBUG-RUN and/or X-DEBUG-INJ headers in the HTTP request.
4.  The vulnerable AgentRuntime function improperly processes these headers.
5.  The system bypasses authentication checks due to the manipulated header values.
6.  The attacker gains unauthorized access to protected resources or functionalities.
7.  The attacker performs privileged actions or exfiltrates sensitive data.

## Impact

Successful exploitation of CVE-2026-7022 allows an attacker to bypass authentication, potentially leading to complete system compromise. This could result in unauthorized access to sensitive data, modification of system configurations, or disruption of services. Given the public availability of the exploit, vulnerable systems are at high risk of attack.

## Recommendation

*   Apply appropriate input validation and sanitization to the `AgentRuntime` function within `packages/core/src/subsystems/AgentManager/AgentRuntime.class.ts` to prevent manipulation of `X-DEBUG-RUN` and `X-DEBUG-INJ` headers (CVE-2026-7022).
*   Deploy the provided Sigma rule to detect exploitation attempts targeting the vulnerable `AgentRuntime` function.
*   Monitor web server logs for HTTP requests containing suspicious `X-DEBUG-RUN` and `X-DEBUG-INJ` headers.
