---
title: OpenClaw Gateway Bearer Auth Bypass After Secret Rotation
slug: 2024-01-openclaw-bearer-auth-bypass
description: OpenClaw versions prior to 2026.4.15 have a vulnerability where gateway HTTP and WebSocket handlers cache bearer-auth configuration at server startup, allowing a revoked token to remain valid after SecretRef rotation until restart, potentially granting unauthorized access.
date: "2024-01-18T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openclaw
  - authentication-bypass
  - secret-rotation
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-xmxx-7p24-h892
rules:
  - title: Detect OpenClaw Authentication Bypass Attempt (Example)
    description: This rule detects potential attempts to use a revoked bearer token after a SecretRef rotation in OpenClaw. This is an example rule, as differentiating between legitimate and malicious use of the old token may be challenging.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Server Restart
    description: This rule detects OpenClaw server restarts which can be used to check for restarts after secret rotation.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw versions before `2026.4.15` are vulnerable to a bearer authentication bypass. The gateway HTTP and WebSocket handlers incorrectly capture the resolved bearer-auth configuration only once, during server startup. Consequently, if a SecretRef rotation occurs, the running gateway continues to accept the old, now-revoked, bearer token. This vulnerability persists until the OpenClaw server is restarted, effectively negating the intended token revocation. This issue poses a significant risk, as it allows potentially unauthorized access even after administrators have taken steps to rotate and invalidate the token. The vulnerability was reported by @zsxsoft, Keen Security Lab, and @qclawer and patched in version `2026.4.15`.

## Attack Chain

1. An attacker obtains a valid bearer token for OpenClaw gateway access.
2. The OpenClaw gateway server starts and caches the resolved bearer-auth configuration.
3. The administrator initiates a SecretRef rotation, intending to revoke the existing bearer token.
4. Due to the vulnerability, the already-running OpenClaw gateway does not re-resolve the bearer-auth configuration against the new secret.
5. The attacker uses the old, now-revoked, bearer token in subsequent HTTP or WebSocket requests.
6. The OpenClaw gateway incorrectly validates the request using the cached, outdated authentication configuration.
7. The attacker gains unauthorized access to the gateway resources.
8. The attacker maintains unauthorized access until the OpenClaw gateway server is restarted.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass intended security controls. Specifically, an attacker with a revoked bearer token can maintain access to OpenClaw gateway resources, even after a SecretRef rotation. The vulnerability affects all OpenClaw deployments running versions prior to `2026.4.15`. The impact is significant, as it undermines the security posture of OpenClaw deployments and could lead to data breaches, service disruption, or other malicious activities.

## Recommendation

*   Upgrade OpenClaw to version `2026.4.15` or later to patch the vulnerability as described in the advisory ([https://github.com/advisories/GHSA-xmxx-7p24-h892](https://github.com/advisories/GHSA-xmxx-7p24-h892)).
*   Restart OpenClaw gateway servers immediately after a SecretRef rotation to ensure that the new authentication configuration is loaded, mitigating the risk if an immediate upgrade is not feasible.
*   Monitor OpenClaw gateway logs for unauthorized access attempts, although this might be difficult to distinguish from legitimate requests using the outdated token.
