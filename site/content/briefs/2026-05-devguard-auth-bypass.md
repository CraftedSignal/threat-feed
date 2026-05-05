---
title: DevGuard Unauthenticated Identity Assertion via X-Admin-Token
slug: 2026-05-devguard-auth-bypass
description: DevGuard versions before 1.2.2 are vulnerable to unauthenticated identity assertion via a client-supplied `X-Admin-Token` HTTP request header, potentially granting attackers full control over organizations if they can guess an admin/owner's Kratos identity UUID.
date: "2026-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication
  - authorization
  - privilege_escalation
  - web_application
vendors:
  - GitHub
  - l3montree-dev
products:
  - devguard
  - devguard API
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/advisories/GHSA-2g9v-7mr5-fgjg
  - https://github.com/l3montree-dev/devguard/commit/6f38310bf93b2a63df3055038f4da82b1f4e6d9a
rules:
  - title: Detect X-Admin-Token Header Without Kratos Cookie
    description: Detects HTTP requests with the `X-Admin-Token` header but lacking a Kratos session cookie, indicating potential exploitation of the DevGuard authentication bypass vulnerability.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1550.002
    data_sources:
      - webserver
      - linux
rules_count: 1
---

DevGuard versions prior to 1.2.2 are susceptible to an unauthenticated identity assertion vulnerability. The `SessionMiddleware` component improperly handles the `X-Admin-Token` HTTP header, using its value directly as the authenticated `userID` when a Kratos session cookie is absent. This allows an attacker to impersonate any user, including organization administrators or owners, by knowing or guessing their Kratos identity UUID. Successful exploitation grants the attacker complete control over the targeted organization's DevGuard resources. The vulnerability was patched in version 1.2.2. This issue poses a significant risk to organizations using affected DevGuard versions, potentially leading to unauthorized access, data breaches, and complete compromise of DevGuard resources.

## Attack Chain

1.  The attacker identifies a target DevGuard instance running a version prior to 1.2.2.
2.  The attacker obtains or guesses the Kratos identity UUID of a target user, ideally an organization admin or owner.
3.  The attacker crafts a malicious HTTP request to the DevGuard API, including the `X-Admin-Token` header set to the target user's Kratos identity UUID.
4.  The DevGuard `SessionMiddleware` processes the request. Since no Kratos session cookie is present, it trusts the `X-Admin-Token` header.
5.  The `SessionMiddleware` incorrectly authenticates the request as the user specified in the `X-Admin-Token` header.
6.  The attacker, now impersonating the target user, sends further API requests to access and manipulate organization resources.
7.  If the impersonated user is an organization administrator or owner, the attacker gains full control over the organization's DevGuard resources.
8.  The attacker may then create new users, modify existing resources, delete data, or perform other administrative actions.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to assume the identity of any user, including organization administrators or owners, within affected DevGuard instances. For administrative users, this leads to complete control over the organization's DevGuard resources, allowing for unauthorized data access, modification, or deletion. The impact could range from data breaches to complete compromise of the targeted organization's DevGuard infrastructure.

## Recommendation

*   Upgrade all DevGuard API instances to version 1.2.2 to remediate the vulnerability as mentioned in the release notes.
*   Implement a reverse proxy to strip the `X-Admin-Token` header from all incoming requests to the DevGuard API as a workaround.
*   Monitor web server logs for the presence of the `X-Admin-Token` header in requests lacking a valid Kratos session cookie, using the provided Sigma rule to detect potential exploitation attempts.
