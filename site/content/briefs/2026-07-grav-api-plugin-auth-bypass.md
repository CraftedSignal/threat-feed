---
title: Grav API Plugin Authorization Bypass Leads to Account Takeover (CVE-2026-65007)
slug: 2026-07-grav-api-plugin-auth-bypass
description: The Grav api plugin (grav-plugin-api) versions prior to 1.0.8 contain an authorization bypass vulnerability where the plugin intercepts API key generation and revocation tasks before proper ACL checks, allowing any user with the baseline admin.login permission to generate or revoke API keys for any account, enabling impersonation, privilege escalation, and potential account takeover.
date: "2026-07-21T12:21:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authorization-bypass
  - privilege-escalation
  - account-takeover
  - cms
vendors:
  - Grav
products:
  - grav-plugin-api
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This allows any user with admin.login to mint a persistent API key bound to any account, and the forged key inherits the target account's API permissions.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: this enables account impersonation and privilege escalation up to account takeover.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: this enables account impersonation and privilege escalation up to account takeover.
    confidence_band: med
cves:
  - id: CVE-2026-65007
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65007
---

A critical authorization bypass vulnerability, identified as CVE-2026-65007, exists in the Grav api plugin (grav-plugin-api) versions prior to 1.0.8. This flaw stems from the plugin's failure to properly authorize API key generation and revocation tasks. Specifically, the plugin intercepts `apiKeyGenerate` and `apiKeyRevoke` admin tasks before the comprehensive account-management Access Control List (ACL) runs, instead authorizing the caller based solely on the `admin.login` permission - a baseline privilege held by every panel user. This design flaw allows any user possessing the fundamental `admin.login` permission to arbitrarily mint or revoke persistent API keys bound to any account. Exploitation of this vulnerability enables account impersonation and significant privilege escalation, potentially leading to full account takeover, especially in environments where API-enabled accounts are configured with elevated or broader permissions. This vulnerability does not require prior advanced privileges beyond basic administrative panel access.

## Attack Chain

1. A malicious user gains or already possesses valid `admin.login` credentials to the Grav admin panel.
2. The malicious user initiates an `apiKeyGenerate` or `apiKeyRevoke` admin task through the Grav system, targeting a higher-privileged account.
3. The `grav-plugin-api` intercepts this request, as designed to handle API key management functions.
4. The plugin performs an insufficient authorization check, validating only the `admin.login` permission, thereby bypassing the more comprehensive account-management ACL.
5. Due to the authorization bypass, an API key is successfully generated for the targeted higher-privileged account, or an existing key is revoked without proper authorization.
6. The malicious user obtains the newly forged API key associated with the victim account.
7. The attacker utilizes the forged API key to impersonate the target account and gains access to its full API permissions.
8. The attacker leverages these inherited permissions to perform unauthorized actions, achieving privilege escalation and potentially full account takeover.

## Impact

The successful exploitation of CVE-2026-65007 can lead to severe consequences for affected Grav installations. Attackers can impersonate any user account, including administrators, and perform actions with their API permissions. This directly enables privilege escalation from a low-privileged `admin.login` user to an administrative user, facilitating complete account takeover. The impact is particularly critical if the targeted API-enabled accounts have broad system permissions, allowing attackers to manipulate content, configurations, and potentially execute arbitrary code depending on the privileges of the impersonated account. This could lead to data theft, website defacement, or further compromise of the underlying server.

## Recommendation

* Immediately patch the Grav api plugin to version 1.0.8 or later to remediate CVE-2026-65007.
* Review the Grav audit logs for unusual `apiKeyGenerate` or `apiKeyRevoke` events, particularly those associated with low-privileged `admin.login` accounts, to identify potential exploitation attempts related to CVE-2026-65007.
