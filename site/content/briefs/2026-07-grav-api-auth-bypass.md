---
title: Grav API Plugin Authorization Bypass (CVE-2026-62231)
slug: 2026-07-grav-api-auth-bypass
description: A critical authorization bypass vulnerability (CVE-2026-62231) in the Grav API plugin versions prior to 1.0.6 allows API keys with restricted scopes to perform any operation the owning user is authorized for, potentially leading to full administrative control of the Grav instance.
date: "2026-07-17T02:35:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - grav
  - cve
  - cms
vendors:
  - Grav
products:
  - Grav API plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: API keys can be created with a restricted scopes array, but the ApiKeyAuthenticator class never reads or enforces these scopes. It loads and returns the owning user's full account object, so a key created with limited scopes (e.g. read-only) can perform any write, delete, or administrative operation the owning user is authorized for.
    confidence_band: high
cves:
  - id: CVE-2026-62231
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62231
  - https://github.com/getgrav/grav/security/advisories/GHSA-x7hm-jc32-v39j
  - https://www.vulncheck.com/advisories/grav-api-key-scope-bypass-via-apikeyauthenticator
---

A significant authorization bypass vulnerability, identified as CVE-2026-62231, affects the Grav API plugin (getgrav/grav-plugin-api) in all versions prior to 1.0.6. This flaw stems from a logical error within the `ApiKeyAuthenticator` class, which is responsible for validating API key permissions. While API keys can be configured with restricted scopes, the authenticator fails to enforce these limitations. Instead, it loads and returns the full account object of the API key's owning user, effectively granting the API key all privileges associated with that user, regardless of its defined scope. This means an API key intended for read-only access could be exploited to perform write, delete, or even administrative operations, leading to unauthorized data modification, deletion, or complete compromise of the Grav content management system. The vulnerability was patched in version 1.0.6 of the Grav API plugin.

## Attack Chain

1. An attacker obtains a legitimate, but scope-restricted, API key for a Grav user account. This key might have been acquired through various means such as phishing, credential stuffing, or other vulnerabilities, but is intended to have limited permissions (e.g., read-only access).
2. The attacker crafts an API request to a Grav endpoint that requires higher privileges than the obtained API key's defined scope (e.g., an endpoint for creating new content, deleting existing users, or modifying system configurations).
3. The malicious request is sent to the Grav API, where the `ApiKeyAuthenticator` class initiates the authentication and authorization process.
4. During authentication, the `ApiKeyAuthenticator` successfully validates the API key as legitimate.
5. Crucially, the `ApiKeyAuthenticator` proceeds to load the full account object of the API key's owning user without actually checking or enforcing the `scopes` array associated with the API key itself.
6. The Grav system grants the attacker's request based on the comprehensive permissions of the owning user, completely disregarding the API key's intended restricted scope.
7. The attacker successfully executes an unauthorized, high-privilege action (e.g., data modification, administrative changes), effectively escalating privileges to the full extent of the owning user's capabilities.

## Impact

Successful exploitation of CVE-2026-62231 can lead to severe consequences for affected Grav instances. If the compromised API key belongs to an administrator, the attacker can achieve full administrative control over the content management system. This enables arbitrary data modification, deletion, or creation, potentially defacing websites, injecting malicious content, or exfiltrating sensitive information. For organizations using Grav as a critical web presence or internal documentation platform, this could result in significant reputational damage, operational disruption, and compliance failures due to data integrity breaches. The number of potential victims includes any organization using unpatched Grav API plugin versions prior to 1.0.6.

## Recommendation

* Patch CVE-2026-62231 immediately by upgrading the Grav API plugin to version 1.0.6 or later.
* Audit existing Grav API keys to ensure they are assigned to users with the least privilege necessary and revoke any unnecessary keys.
* Monitor web server and Grav application logs for unusual API activity, particularly requests from API keys performing actions outside their expected scope.
