---
title: yamcs-core Authentication Endpoint Brute-Force Vulnerability (CVE-2026-44596)
slug: 2026-05-yamcs-auth-bypass
description: A public exploit has been published for CVE-2026-44596, a vulnerability in yamcs-core where the /auth/token authentication endpoint lacks rate limiting, allowing unauthenticated remote attackers to perform unlimited password guessing attempts against any user account, fixed in version 5.12.7.
date: "2026-05-29T14:02:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - authentication
  - brute-force
vendors:
  - Yamcs
products:
  - yamcs-core
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://sploitus.com/exploit?id=26680C7D-63B4-5F68-AA47-63A6A3ADADD4&utm_source=rss&utm_medium=rss
  - CVE-2026-44596
rules:
  - title: Detect Excessive Authentication Attempts to yamcs-core /auth/token
    description: Detects a high number of POST requests to the yamcs-core /auth/token endpoint, indicating potential brute-force attempts related to CVE-2026-44596.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
rules_count: 1
---

A publicly available exploit exists for CVE-2026-44596, a medium-severity vulnerability affecting yamcs-core versions prior to 5.12.7. Discovered by Daniel Miranda Barcelona (Excal1bur), the vulnerability stems from the absence of rate limiting, account lockout mechanisms, or failed attempt throttling on the `/auth/token` authentication endpoint. This lack of protection enables unauthenticated remote attackers to conduct brute-force attacks against user accounts by making unlimited password guessing attempts, potentially leading to unauthorized access to the system. The vulnerability was reported in May 2026, and a fix was released in yamcs-core version 5.12.7 on May 27, 2026. Defenders should upgrade to version 5.12.7 or later to mitigate the risk.

## Attack Chain

1.  An unauthenticated attacker identifies a yamcs-core instance with a vulnerable version (<= 5.12.6).
2.  The attacker crafts an HTTP POST request targeting the `/auth/token` endpoint.
3.  The POST request includes a username and a guessed password within the request body.
4.  The attacker sends the POST request to the `/auth/token` endpoint without any delay or limitation on the number of attempts.
5.  The yamcs-core server processes the authentication request without rate limiting or account lockout mechanisms.
6.  If the guessed password is incorrect, the server responds with an authentication failure, but does not prevent further attempts.
7.  The attacker repeats steps 2-6 with different password variations, automating the process to attempt a large number of password combinations.
8.  If a correct password is guessed, the server grants the attacker an authentication token, allowing them to access protected resources.

## Impact

Successful exploitation of CVE-2026-44596 can allow unauthorized access to yamcs-core systems. Attackers can potentially compromise user accounts through brute-force attacks due to the lack of rate limiting on the authentication endpoint. This could lead to data breaches, system manipulation, or other malicious activities, depending on the privileges of the compromised account. Organizations using affected versions of yamcs-core are at risk until they upgrade to version 5.12.7 or later.

## Recommendation

*   Upgrade yamcs-core to version 5.12.7 or later to patch CVE-2026-44596.
*   Implement rate limiting on the `/auth/token` endpoint at the application or infrastructure level, regardless of patching status (mitigation control).
*   Monitor web server logs for excessive POST requests to the `/auth/token` endpoint, using a detection rule like "Detect Excessive Authentication Attempts to yamcs-core /auth/token".
