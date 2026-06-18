---
title: PraisonAI Platform Vulnerable to JWT Forgery via Hardcoded Default Secret
slug: 2026-06-praisonai-platform-jwt-secret-forgery
description: The `praisonai-platform` package, versions 0.1.4 and below, is critically vulnerable to authentication bypass and privilege escalation due to a hardcoded default JWT signing secret (`dev-secret-change-me`) that is inadvertently enabled in default deployments, allowing an unauthenticated attacker to forge JWTs and impersonate any user.
date: "2026-06-18T14:43:44Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - hardcoded-credentials
  - jwt-forgery
  - python
  - supply-chain
  - misconfiguration
vendors:
  - MervinPraison
products:
  - praisonai-platform <= 0.1.4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/advisories/GHSA-cwj8-6gp2-ggcw
iocs:
  - type: url
    value: https://github.com/MervinPraison/PraisonAI
  - type: hash_sha256
    value: cc29d43c5412da2c73c818859b8d8b146587842999b777336017ab9d9e509258
  - type: string
    value: dev-secret-change-me
ioc_counts:
  hash_sha256: 1
  string: 1
  url: 1
rules:
  - title: Detect PraisonAI Platform Vulnerable File (SHA256)
    description: Detects the presence of the `praisonai_platform/services/auth_service.py` file with the specific vulnerable SHA256 hash, indicating a potentially misconfigured PraisonAI Platform instance.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1195.002
      - T1552.004
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Administrative Access from Unusual Source IPs via PraisonAI Platform API
    description: Detects successful access attempts to administrative endpoints on the PraisonAI Platform, specifically from source IP addresses that are unusual or not whitelisted for administrative access, potentially indicating authentication bypass or privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1070.004
      - T1078.001
    data_sources:
      - webserver
rules_count: 2
---

The `praisonai-platform` Python package, specifically versions 0.1.4 and older, developed by Mervin Praison, contains a critical vulnerability where its JSON Web Token (JWT) signing secret defaults to a publicly known string, `dev-secret-change-me`. This misconfiguration stems from a flawed environment variable check in `praisonai_platform/services/auth_service.py` (SHA256: `cc29d43c5412da2c73c818859b8d8b146587842999b777336017ab9d9e509258`). The intended guard to prevent production deployments with the default secret fails if both `PLATFORM_JWT_SECRET` and `PLATFORM_ENV` are left unset, causing the application to silently start with the insecure secret. This enables unauthenticated attackers to forge arbitrary JWTs, effectively bypassing authentication for any user, including administrative accounts, across all routes protected by the `get_current_user` dependency.

## Attack Chain

1.  **Initial Access / Reconnaissance**: An unauthenticated attacker identifies a `praisonai-platform` instance, possibly by interacting with its API endpoints or discovering the underlying software version.
2.  **Vulnerability Identification**: The attacker identifies that the application is running `praisonai-platform` version 0.1.4 or earlier and has not correctly configured its `PLATFORM_JWT_SECRET` and `PLATFORM_ENV` environment variables, leading to the use of the default `dev-secret-change-me` JWT secret.
3.  **Token Forgery**: Using the publicly known JWT secret (`dev-secret-change-me`) and the HS256 algorithm, the attacker crafts a JWT with arbitrary claims, including `sub` (user ID) and `email`, for a target user (e.g., an administrative user like `admin@example.com` or a known user ID).
4.  **Authentication Bypass**: The attacker sends the forged JWT in an `Authorization` header to a protected endpoint (e.g., `/api/v1/workspaces`, `/api/v1/projects`).
5.  **User Impersonation**: The `praisonai-platform` server validates the forged token using the default secret and treats the attacker as the impersonated user (e.g., `admin-user-id-attacker-chose`).
6.  **Privilege Escalation / Unauthorized Access**: If the forged token impersonates an administrator or a member of a specific workspace, the attacker gains full access to that user's resources and permissions within the application, including creating, modifying, or deleting data.
7.  **Impact**: The attacker proceeds to exfiltrate data, tamper with application settings, or perform other malicious actions as the impersonated user.

## Impact

This critical vulnerability directly leads to complete authentication bypass and privilege escalation within affected `praisonai-platform` deployments. An attacker can impersonate any user, including administrators, by forging JWTs with arbitrary user IDs and email addresses. All routes protected by the `get_current_user` dependency, which includes core functionalities such as managing workspaces, projects, issues, agents, and labels, become vulnerable to unauthorized access. The consequence is full compromise of the application's data and functionality, with potential for sensitive data exfiltration, system configuration changes, and disruption of service. There is no specific victim count, but any instance of `praisonai-platform` running the vulnerable versions without proper environment configuration is at risk.

## Recommendation

*   **Immediate Action**: Patch `praisonai-platform` to a version that addresses this vulnerability or ensure `PLATFORM_JWT_SECRET` is set to a strong, random, and unique value (at least 32 bytes) in all environments, including development. Set `PLATFORM_ENV` to a non-`dev` value (e.g., `production`) for production deployments to ensure the built-in guard is active.
*   **Detection Engineering**: Deploy the provided Sigma rule "Detect PraisonAI Platform Vulnerable File (SHA256)" to identify instances running the vulnerable `auth_service.py` file.
*   **Supply Chain Security**: Implement automated scanning for component vulnerabilities (SCA) to identify the presence of `praisonai-platform <= 0.1.4` in your software supply chain.
*   **Log Configuration**: Ensure application logs are configured to capture environment variable settings on process startup, if possible, to detect instances where `PLATFORM_JWT_SECRET` is unset or `PLATFORM_ENV` defaults to `dev`.
