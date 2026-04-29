---
title: LiteLLM Authentication Bypass via Password Hash Exposure and Pass-the-Hash
slug: 2024-01-09-litellm-auth-bypass
description: LiteLLM versions before 1.83.0 stored user passwords as unsalted SHA-256 hashes and exposed these hashes through multiple API endpoints, enabling an authenticated user to retrieve another user's password hash and use it to log in as that user due to the /v2/login endpoint accepting the raw SHA-256 hash without re-hashing, leading to potential privilege escalation.
date: "2026-04-08T00:04:12Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - litellm
  - authentication-bypass
  - credential-access
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-69x8-hrgq-fjj8
rules:
  - title: Detect LiteLLM User Info Hash Access
    description: Detects access to the /user/info endpoint, which exposes user password hashes in LiteLLM versions prior to 1.83.0.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.002
    data_sources:
      - webserver
      - linux
  - title: Detect LiteLLM Login with SHA256 Hash
    description: Detects login attempts to the /v2/login endpoint using a 64-character hexadecimal string as the password, indicating a potential pass-the-hash attack in LiteLLM.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

LiteLLM versions prior to 1.83.0 are vulnerable to an authentication bypass vulnerability. User passwords are stored as unsalted SHA-256 hashes, a weak cryptographic practice that makes them susceptible to rainbow table attacks. Furthermore, these password hashes are exposed through several API endpoints, including `/user/info`, `/user/update`, and `/spend/users`, allowing any authenticated user to retrieve them. The `/v2/login` endpoint also accepts the raw SHA-256 hash as a valid password without proper re-hashing. This combination of vulnerabilities allows an attacker with low-level access to escalate privileges by obtaining another user's password hash and using it to directly log in as that user. Defenders should upgrade to version 1.83.0 or later to mitigate this vulnerability.

## Attack Chain

1. Attacker gains initial access to LiteLLM and authenticates as a low-privilege user.
2. Attacker sends a request to `/user/info` to retrieve the password hash of another user.
3. The API responds with the target user's SHA-256 password hash.
4. Attacker sends a POST request to the `/v2/login` endpoint using the stolen SHA-256 hash as the password.
5. The `/v2/login` endpoint accepts the raw SHA-256 hash without re-hashing.
6. The server authenticates the attacker as the target user.
7. Attacker now has the privileges of the target user, potentially gaining access to sensitive data or administrative functions.

## Impact

Successful exploitation of this vulnerability leads to unauthorized access and privilege escalation within the LiteLLM application. An attacker can impersonate other users, including administrators, potentially leading to data breaches, system compromise, and unauthorized modifications. The number of victims depends on the deployment size, but any LiteLLM instance running a version prior to 1.83.0 is vulnerable. Sectors utilizing LiteLLM are at risk.

## Recommendation

*   Upgrade LiteLLM to version 1.83.0 or later to patch the vulnerability (reference: Patches section).
*   Deploy the Sigma rule "Detect LiteLLM User Info Hash Access" to monitor for unauthorized access to user password hashes via the `/user/info` endpoint (reference: rule: "Detect LiteLLM User Info Hash Access").
*   Deploy the Sigma rule "Detect LiteLLM Login with SHA256 Hash" to detect login attempts using SHA256 hashes (reference: rule: "Detect LiteLLM Login with SHA256 Hash").
