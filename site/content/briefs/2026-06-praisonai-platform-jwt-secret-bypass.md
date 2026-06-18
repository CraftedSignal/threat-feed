---
title: Praisonai-platform Critical Authentication Bypass Due to Persistent Hardcoded JWT Secret
slug: 2026-06-praisonai-platform-jwt-secret-bypass
description: Praisonai-platform versions up to and including 0.1.4 are vulnerable to a critical authentication bypass stemming from a hardcoded JWT signing secret ('dev-secret-change-me') and a bypassed production guard, allowing unauthenticated attackers to forge JSON Web Tokens (JWTs) and impersonate any user, leading to complete access, privilege escalation to workspace owner, and potential resource destruction.
date: "2026-06-18T14:45:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - hardcoded-credentials
  - jwt
  - python
  - web-application
  - supply-chain
vendors:
  - PraisonAI
products:
  - praisonai-platform (<= 0.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
references:
  - https://github.com/advisories/GHSA-f38v-77qj-h4jq
iocs:
  - type: credential
    value: dev-secret-change-me
ioc_counts:
  credential: 1
rules:
  - title: Detect Praisonai-Platform Default Secret Guard RuntimeError
    description: Detects the specific RuntimeError message that indicates praisonai-platform is attempting to use the hardcoded default JWT secret 'dev-secret-change-me' in a non-'dev' environment, signaling a critical misconfiguration.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
  - title: Detect Praisonai-Platform Uvicorn Default Startup
    description: Detects the common startup command for praisonai-platform using uvicorn, which in its default configuration (without PLATFORM_JWT_SECRET environment variable) is vulnerable to JWT forgery. This rule helps identify vulnerable instances.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `praisonai-platform` (PyPI) package, specifically versions up to and including 0.1.4, is critically vulnerable to an authentication bypass. Despite a previous advisory (GHSA-3qg8-5g3r-79v5) claiming a patch in 0.1.4, the vulnerability persists. The platform's JSON Web Tokens (JWTs) are signed using a hardcoded secret, "dev-secret-change-me", which is publicly known from the source code. The intended production guard, designed to prevent this, is default-open because it only triggers when `PLATFORM_ENV` is *not* "dev", but `PLATFORM_ENV` defaults to "dev" if not explicitly set. This flaw allows any unauthenticated attacker to forge valid JWTs, impersonate any user (including workspace owners), and gain complete unauthorized access. This issue affects any default deployment of `praisonai-platform` 0.1.4 that does not explicitly set a strong `PLATFORM_JWT_SECRET`.

## Attack Chain

1.  **Reconnaissance**: Attacker identifies a `praisonai-platform` instance, potentially using `uvicorn praisonai_platform.api.app:app` or `python -m praisonai_platform`.
2.  **Information Gathering**: Attacker accesses the public source code of `praisonai-platform` 0.1.4 to retrieve the hardcoded JWT secret "dev-secret-change-me".
3.  **Credential Forgery**: Attacker crafts a malicious JWT payload (e.g., `{"sub": "target_user_id", "email": "victim@target", "exp": "future_timestamp"}`).
4.  **JWT Signing**: Attacker signs the crafted JWT payload using the publicly known `dev-secret-change-me` secret and the `HS256` algorithm.
5.  **Authentication Bypass**: Attacker sends requests to the `praisonai-platform` API with the forged JWT in the `Authorization` header. The platform's `_verify_token` function, also using the default secret, validates the token and authenticates the attacker as `target_user_id`.
6.  **Privilege Escalation**: If the `target_user_id` is a known workspace owner's ID (which can be discovered from member listings or logs), the attacker gains owner-level access to the workspace.
7.  **Impact**: Attacker leverages owner privileges to perform actions such as deleting workspaces, evicting legitimate members, or exfiltrating data, leading to resource destruction or denial of service.

## Impact

Any deployment of `praisonai-platform` 0.1.4 that runs without explicitly setting a strong `PLATFORM_JWT_SECRET` is immediately vulnerable. This includes the default startup commands like `python -m praisonai_platform --host 0.0.0.0 --port 8000` which do not configure the necessary environment variables. The direct consequences include complete unauthenticated authentication bypass, allowing an attacker to mint valid session tokens for any user. With a known user ID (obtainable from member lists or logs), attackers can achieve workspace-owner takeover, leading to the read, update, and deletion of all resources within that workspace, and member management. This enables resource destruction and lock-out, such as deleting entire workspaces or evicting legitimate users, resulting in an irrecoverable denial of service. The initial vulnerability (GHSA-3qg8) was scored 9.8 Critical on CVSS.

## Recommendation

*   Immediately update `praisonai-platform` to a version where the vulnerability is confirmed patched, or implement the suggested fix to remove the default secret and enforce `PLATFORM_JWT_SECRET` at startup.
*   Review application logs for the presence of the `RuntimeError` message indicating the default secret is in use in a production environment, as described in the `Detect Praisonai-Platform Default Secret Guard RuntimeError` Sigma rule.
*   Search code repositories and configuration files for the hardcoded secret `dev-secret-change-me` to ensure it's not present in active deployments.
*   Deploy the `Detect Praisonai-Platform Uvicorn Default Startup` Sigma rule to identify systems running the vulnerable application entry point.
*   Rotate all JWT signing keys if this secret has been used in any production environment, assuming compromise.
