---
title: LiteLLM Authentication Bypass via Password Hash Exposure and Pass-the-Hash
slug: 2024-01-09-litellm-auth-bypass
description: LiteLLM versions before 1.83.0 stored user passwords as unsalted SHA-256 hashes and exposed these hashes through multiple API endpoints, enabling an authenticated user to retrieve another user's password hash and use it to log in as that user due to the /v2/login endpoint accepting the raw SHA-256 hash without re-hashing, leading to potential privilege escalation.
date: "2026-04-08T00:04:12Z"
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

LiteLLM versions prior to 1.83.0 are vulnerable to an authentication bypass vulnerability. User passwords are stored as unsalted SHA-256 hashes, a weak cryptographic practice that makes them susceptible to rainbow table attacks. Furthermore, these password hashes are exposed through several API endpoints, including `/user/info`, `/user/update`, and `/spend/users`, allowing any authenticated user to retrieve them. The `/v2/login` endpoint also accepts the raw SHA-256 hash as a valid password…
