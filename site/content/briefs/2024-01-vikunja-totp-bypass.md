---
title: Vikunja TOTP Two-Factor Authentication Bypass via OIDC Login
slug: 2024-01-vikunja-totp-bypass
description: Vikunja version 2.2.2 and earlier has a two-factor authentication bypass vulnerability via the OIDC login path, where TOTP enrollment is ignored when a local user with TOTP enabled is matched via OIDC email fallback, allowing attackers with a matching email address in the OIDC provider to gain access without the second factor.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vikunja
  - totp
  - oidc
  - bypass
  - cve-2026-34727
vendors:
  - Vikunja
products:
  - Vikunja
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://github.com/advisories/GHSA-8jvc-mcx6-r4cg
iocs:
  - type: url
    value: http://localhost:3456
  - type: url
    value: http://localhost:5556
  - type: email
    value: alice@test.com
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect Vikunja Successful OIDC Login Bypassing TOTP
    description: Detects successful OIDC logins where the user also has TOTP enabled, potentially indicating a bypass of the second factor.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Vikunja OIDC Callback Request
    description: Detects requests to the Vikunja OIDC callback endpoint, which could indicate an attempt to exploit the TOTP bypass vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Vikunja, a self-hostable to-do list application, is vulnerable to a two-factor authentication bypass (CVE-2026-34727) affecting versions 2.2.2 and earlier. The vulnerability arises in the OIDC (OpenID Connect) login flow when the `EmailFallback` option is enabled. If a local user has TOTP (Time-Based One-Time Password) enabled and their email address matches a user authenticating through the OIDC provider, the TOTP check is skipped. This allows an attacker who can authenticate to the OIDC provider with a matching email address to bypass the TOTP requirement and gain unauthorized access to the Vikunja account. This issue stems from the OIDC callback handler (`pkg/modules/auth/openid/openid.go`) issuing a JWT without verifying TOTP status.

## Attack Chain

1.  The attacker identifies a Vikunja instance with OIDC enabled and `EmailFallback` set to `true`.
2.  The attacker identifies a valid local user with TOTP enabled and determines the user's email address.
3.  The attacker creates or compromises an account on the configured OIDC provider that uses the same email address as the target Vikunja user.
4.  The attacker initiates the OIDC login flow to the Vikunja instance.
5.  The OIDC provider authenticates the attacker using their compromised or created account.
6.  Vikunja's OIDC callback handler (`pkg/modules/auth/openid/openid.go`) matches the email address from the OIDC provider to the local user.
7.  The callback handler incorrectly issues a JWT without performing TOTP verification, bypassing the second factor.
8.  The attacker uses the received JWT to authenticate to the Vikunja API and gains full access to the user's account.

## Impact

Successful exploitation allows an attacker to bypass TOTP two-factor authentication and gain unauthorized access to Vikunja accounts. This can lead to data breaches, modification of tasks and projects, and potential further compromise of the Vikunja instance. Any user who has enrolled TOTP on their local account can have that protection completely bypassed if their email address is also present in the OIDC provider. This undermines the security of TOTP enrollment.

## Recommendation

*   Apply the recommended fix by adding a TOTP check in the OIDC callback before issuing the JWT, as described in the advisory.
*   Disable the `EmailFallback` option in the Vikunja OIDC configuration until the patch is applied.
*   Monitor Vikunja logs for unusual OIDC login activity, specifically successful OIDC logins for users who also have local accounts with TOTP enabled.
*   Deploy the Sigma rule `Detect Vikunja Successful OIDC Login Bypassing TOTP` to identify successful logins that bypass TOTP.
*   Deploy the Sigma rule `Detect Vikunja OIDC Callback Request` to identify potential OIDC login attempts.
