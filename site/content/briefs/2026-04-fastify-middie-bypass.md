---
title: '@fastify/middie Middleware Bypass Vulnerability (CVE-2026-33804)'
slug: 2026-04-fastify-middie-bypass
description: A middleware bypass vulnerability (CVE-2026-33804) exists in @fastify/middie versions 9.3.1 and earlier when the deprecated Fastify ignoreDuplicateSlashes option is enabled, potentially allowing unauthorized access.
date: "2026-04-16T15:17:34Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - fastify
  - middie
  - middleware
  - bypass
  - cve-2026-33804
  - defense-evasion
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
cves:
  - id: CVE-2026-33804
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33804
rules:
  - title: Detect Fastify Middie Bypass Attempt
    description: Detects potential attempts to bypass @fastify/middie middleware by exploiting CVE-2026-33804 using duplicate slashes in the request URI.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: Detect Fastify Middie Bypass Attempt - HTTP Method
    description: Detects potential attempts to bypass @fastify/middie middleware by exploiting CVE-2026-33804 using duplicate slashes in the request URI and specific HTTP Methods.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

@fastify/middie, a Fastify middleware engine, is vulnerable to a significant security bypass. Specifically, versions 9.3.1 and earlier are susceptible when the deprecated Fastify `ignoreDuplicateSlashes` option is enabled. This vulnerability, identified as CVE-2026-33804, arises because the middleware's path matching logic fails to account for the duplicate slash normalization performed by Fastify's router. Consequently, crafted HTTP requests containing duplicate slashes can circumvent middleware authentication and authorization checks, potentially granting unauthorized access to protected resources. This vulnerability only affects applications that are actively using the deprecated `ignoreDuplicateSlashes` option. The recommended remediation is to upgrade to @fastify/middie version 9.3.2, which addresses this issue. Alternatively, disabling the `ignoreDuplicateSlashes` option can serve as a mitigation.

## Attack Chain

1. An attacker identifies a Fastify application using @fastify/middie version 9.3.1 or earlier with the `ignoreDuplicateSlashes` option enabled.
2. The attacker crafts a malicious HTTP request targeting a protected resource. The request URI includes duplicate slashes (e.g., `/api//resource`).
3. The request is received by the Fastify server.
4. Fastify's router normalizes the duplicate slashes in the URI before passing it to the middleware.
5. The middleware's path matching logic fails to correctly handle the normalized URI due to the `ignoreDuplicateSlashes` setting.
6. As a result, the request bypasses the intended authentication and/or authorization checks implemented by the middleware.
7. The request reaches the targeted resource, which is processed by the application.
8. The attacker gains unauthorized access to the resource, potentially leading to data breaches, privilege escalation, or other malicious activities.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass authentication and authorization controls, potentially gaining unauthorized access to sensitive data or functionality within the Fastify application. The severity of the impact depends on the nature of the protected resources and the extent of the attacker's access. This could lead to data breaches, privilege escalation, or other malicious activities. The number of potential victims is dependent on the number of applications using the vulnerable version of @fastify/middie with the `ignoreDuplicateSlashes` option enabled.

## Recommendation

*   Upgrade @fastify/middie to version 9.3.2 or later to patch the vulnerability described in CVE-2026-33804.
*   Disable the `ignoreDuplicateSlashes` option in Fastify configurations as an alternative mitigation.
*   Deploy the Sigma rule `DetectFastifyMiddieBypassAttempt` to identify potential exploitation attempts based on duplicate slashes in the request URI.
