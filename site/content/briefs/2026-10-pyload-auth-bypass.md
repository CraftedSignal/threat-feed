---
title: Authentication Bypass and Brute-Force Oracle in pyload-ng
slug: 2026-10-pyload-auth-bypass
description: An insecure permission check in the pyload-ng API allows any authenticated user to perform administrative password brute-forcing via a side-channel oracle.
date: "2026-10-09T21:25:58Z"
lastmod: "2026-10-09T21:27:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - authentication-bypass
  - web-application
vendors:
  - pyLoad
products:
  - pyload-ng (>= 0.5.0b3.dev1, <= 0.5.0b3.dev101)
  - pyLoad-ng (<= 0.5.0b3.dev101)
affected_os:
  - linux
  - windows
  - macos
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: An attacker holding the lowest-privileged account in the system therefore has a clean binary oracle on the administrator password.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows an attacker to create device nodes or FIFOs during extraction, facilitating system-level compromises.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-68w4-83fh-f2w8
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review logs for high volumes of 200 OK responses from /api/getUserData or /api/get_userdata
      owner: SOC
      due: 24h
      evidence: Endpoint used as brute-force oracle
  mitigation_plan:
    - priority: immediate
      action: Configure rate limiting to use remote_addr instead of X-Forwarded-For
      owner: IT Operations
      addresses: API rate limit bypass
      evidence: Rate limiting is bypassable by rotating X-Forwarded-For
updates:
  - at: "2026-10-09T21:27:44Z"
    level: L2
    summary: added coverage for pyLoad-ng (<= 0.5.0b3.dev101)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-fr26-jjhm-638c
---

Research has identified a critical vulnerability in pyload-ng (versions 0.5.0b3.dev1 through 0.5.0b3.dev101) originating from an incorrectly implemented permission gate. The `Api.getUserData` and `Api.get_userdata` endpoints are decorated with `@permission(Perms.ANY)`. In the pyload-ng codebase, `Perms.ANY` is defined as `0`, and the permission validation logic uses a bitmask AND operation. Consequently, any authenticated session, regardless of privileges, satisfies the `has_permission` check. These endpoints act as thin wrappers around the internal `check_auth` method, which is intended to be restricted to administrators. By passing an arbitrary password to these endpoints, an attacker can determine if the password is valid based on the API response, creating a high-speed brute-force oracle. This vulnerability is significantly amplified by the lack of account lockout mechanisms and a flaw in the rate-limiting implementation that permits bypassing by rotating the `X-Forwarded-For` HTTP header.

## Attack Chain

1. Attacker gains access to a low-privileged account on a pyload-ng instance (e.g., `role=USER`, `permission=0`).
2. Attacker initiates an authenticated session using their own credentials.
3. Attacker identifies the target administrative account (e.g., 'pyload').
4. Attacker constructs a script to iterate through password guesses using the `/api/getUserData` endpoint.
5. For each attempt, the attacker modifies the `X-Forwarded-For` header to bypass the 100 req/min rate limit bucket.
6. Attacker monitors the HTTP response: a `200 OK` with null data indicates an incorrect password, while a `200 OK` with user details confirms successful authentication.
7. Upon identifying the correct password, the attacker authenticates as the administrator via the `/login` endpoint.
8. Attacker uses administrative privileges to exfiltrate all user data or perform other unauthorized actions.

## Impact

Successful exploitation results in full administrative takeover of the pyload-ng instance. An attacker can recover the administrator's password via automated brute force, as there are no failed-login throttles or account lockout policies. Once the admin account is compromised, the attacker gains complete control over the application, including the ability to dump sensitive user data and credentials stored in the system.

## Recommendation

- Upgrade to a patched version of pyload-ng as soon as a fix is available, or remove the vulnerable `getUserData` and `get_userdata` methods if they are not required.
- Implement strict ingress filtering for web traffic to ensure that the `X-Forwarded-For` header is only trusted when originating from a validated, internal proxy.
- Configure the web server to use the real client IP address for rate-limiting calculations instead of trusting client-supplied headers.
- Apply granular rate limiting or account lockout policies to mitigate automated brute-force attempts.
- Enable account-level monitoring for unusual spikes in failed authentication attempts directed at administrative accounts.
