---
title: Sync-in Server 2FA Bypass via Token API
slug: 2026-09-sync-in-2fa-bypass
description: Sync-in Server v2.3.0 and earlier is vulnerable to a 2FA bypass in the /api/auth/token endpoint, allowing attackers with known credentials to obtain unrestricted JWTs without providing TOTP codes.
date: "2026-09-22T19:53:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sync_in:server:*:*:*:*:*:*:*:*
tags:
  - 2fa-bypass
  - authentication-bypass
  - webserver
vendors:
  - Sync-in
products:
  - Sync-in Server (<= 2.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An attacker who already knows valid credentials for a 2FA-enabled account can bypass 2FA in a single request.
    confidence_band: high
cves:
  - id: CVE-2026-58269
    cvss: 8.1
references:
  - https://github.com/advisories/GHSA-92cr-jxw4-5wjg
rules:
  - title: Detect Sync-in Token API Authentication Usage
    description: Detects usage of the /api/auth/token endpoint which is vulnerable to 2FA bypass. Monitoring this endpoint allows for identification of potential abuse.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1550.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review logs for traffic to /api/auth/token as a high priority lead
      owner: SOC
      due: 24h
      evidence: Endpoint is identified as the entry point for 2FA bypass
  mitigation_plan:
    - priority: immediate
      action: Upgrade Sync-in Server to 2.4.0 or later
      owner: IT Operations
      addresses: CVE-2026-58269
      evidence: Source advisory recommends remediation by gating the endpoint
---

Sync-in Server versions 2.3.0 and earlier contain a security vulnerability in the /api/auth/token endpoint that results in a complete bypass of TOTP two-factor authentication. While the standard /api/auth/login endpoint correctly enforces 2FA by checking the user's twoFaEnabled status and requiring a token verification flow, the /api/auth/token endpoint relies solely on the AuthLocalGuard for username and password validation. Upon successful authentication, the server immediately issues unrestricted Bearer access and refresh JWTs without verifying the TOTP status. This allows an attacker who already possesses valid user credentials to generate a valid session token, effectively neutralizing the security provided by 2FA. This flaw highlights an inconsistency in security policy implementation between the server's authentication routes, specifically within auth.controller.ts and auth.service.ts.

## Attack Chain

1. Attacker obtains valid username and password credentials for a target user via prior reconnaissance or credential harvesting.
2. Attacker inspects target environment to confirm it is a Sync-in Server instance running version 2.3.0 or earlier.
3. Attacker identifies the /api/auth/token endpoint as a potential authentication route during application profiling.
4. Attacker constructs a POST request to /api/auth/token containing the valid username and password of the 2FA-enabled target account.
5. The Sync-in Server processes the request, validating credentials via AuthLocalGuard, but fails to check the user.twoFaEnabled status.
6. The server generates and returns a JSON response containing unrestricted Bearer access and refresh JWTs to the attacker.
7. Attacker uses the acquired Bearer token in the Authorization header to authenticate against protected API endpoints, such as /api/users/me.
8. The server accepts the forged session, granting the attacker unauthorized access to the target's account and profile data without a second factor.

## Impact

Successful exploitation allows an attacker to bypass multi-factor authentication, granting them full access to the target's account. This leads to unauthorized data exfiltration, account takeover, and potential lateral movement within the application environment. Any account with 2FA enabled is vulnerable, significantly reducing the security posture of the organization.

## Recommendation

Prioritized actions for detection engineering teams:
- Deploy detection for anomalous HTTP POST requests to /api/auth/token originating from non-standard user agents or IPs associated with external reconnaissance.
- Implement monitoring for a high volume of failed or successful authentication attempts targeted specifically at the /api/auth/token endpoint compared to the standard /api/auth/login route.
- Patch Sync-in Server to a version later than 2.3.0 that implements the 2FA gate within the token endpoint logic.
- Audit logs for instances where access tokens are issued to users with twoFaEnabled set to true without a preceding successful 2FA verification event.
