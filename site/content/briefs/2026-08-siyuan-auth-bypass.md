---
title: Brute-Force Vulnerability in SiYuan Kernel API Authentication
slug: 2026-08-siyuan-auth-bypass
description: SiYuan kernel versions prior to 3.7.4 contain a flaw in the CheckAuth() middleware that permits unlimited authentication attempts against API tokens, enabling attackers to gain administrative access.
date: "2026-08-16T14:25:22Z"
lastmod: "2026-08-17T12:47:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - credential-brute-force
  - web-application
  - vulnerability
  - path-traversal
vendors:
  - SiYuan
products:
  - SiYuan kernel
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: An unauthenticated remote attacker can perform unlimited automated guesses of the API token.
    confidence_band: high
cves:
  - id: CVE-2026-73056
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73056
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74798
  - https://github.com/advisories/GHSA-7hm9-v7vf-7g4w
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch SiYuan kernel to 3.7.4 or higher
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-73056
  hunt_leads:
    - lead: High-frequency authentication attempts to API endpoints
      technique_id: T1110.001
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The middleware fails to apply CAPTCHA or account lockout protections to API token authentication requests.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to SiYuan API endpoints to trusted IP ranges
      owner: Network Security
      addresses: CVE-2026-73056
      evidence: Unauthenticated remote attacker can perform unlimited automated guesses
updates:
  - at: "2026-08-17T12:47:53Z"
    level: L2
    summary: added coverage for SiYuan kernel
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74798
---

SiYuan kernel versions before 3.7.4 are susceptible to an authentication bypass vulnerability within the CheckAuth() middleware. The vulnerability arises because the middleware, which processes authentication for the API, fails to integrate with the application's global protection mechanisms such as CAPTCHA challenges or account lockout policies (NeedCaptcha/WrongAuthCount). This oversight allows an unauthenticated remote attacker to perform rapid, automated brute-force guessing of the API token (Conf.Api.Token) via either an Authorization header or a URL query parameter. 

Successful exploitation grants the attacker RoleAdministrator privileges, which provides full control over the application, including the ability to execute arbitrary SQL queries and perform file system operations. This is particularly critical in environments where administrators have configured weak or short custom tokens. Organizations using SiYuan must prioritize updating to version 3.7.4 or higher to enforce proper authentication throttling.

## Impact

Successful exploitation results in full administrative takeover of the SiYuan application instance. This allows attackers to perform unauthorized data exfiltration via SQL queries, modify or delete sensitive data, and manipulate the underlying server file system, potentially leading to persistent backdoors or full system compromise.

## Recommendation

- Upgrade all SiYuan kernel instances to version 3.7.4 or later immediately.
- Audit current API token configurations to ensure they meet strong entropy requirements if immediate patching is not possible.
- Monitor web application logs for high-frequency POST or GET requests to the SiYuan API endpoints containing token-related parameters or headers originating from a single IP address.
