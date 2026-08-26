---
title: Authorization Bypass in grav-plugin-api
slug: 2026-08-grav-plugin-auth-bypass
description: The grav-plugin-api plugin for Grav CMS (before version 1.0.18) contains an authorization flaw in UsersController.php that allows API keys with restricted scopes to perform sensitive administrative actions against super-admin accounts.
date: "2026-08-26T16:20:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Grav
products:
  - grav-plugin-api
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The grav-plugin-api plugin before 1.0.18 does not enforce API-key scope in the requireNotSuperTarget() function in UsersController.php across seven sensitive user-management endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-80203
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80203
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade grav-plugin-api to 1.0.18
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability notice recommends version 1.0.18 as the fix.
---

The Grav CMS plugin grav-plugin-api, specifically versions prior to 1.0.18, contains a critical authorization vulnerability (CVE-2026-80203) within the `UsersController.php` file. The vulnerability stems from the `requireNotSuperTarget()` function, which incorrectly validates the authorization scope of API keys. 

Instead of verifying if a specific API key possesses the required authority via `isSuperWithinScope()`, the function checks if the acting user account has global super-admin status. Consequently, an attacker holding a compromised or limited API key associated with a super-admin account can bypass intended scoping restrictions. This allows the attacker to execute unauthorized administrative actions - such as disabling multi-factor authentication (2FA), modifying or deleting avatars, and managing (minting or deleting) other API keys - against other super-admin accounts. The issue affects seven distinct user-management endpoints, posing a severe risk to administrative control and account integrity within Grav CMS environments.

## Impact

Successful exploitation allows for unauthorized account management, potential privilege escalation, and loss of administrative account security. Affected organizations face the risk of account takeover and 2FA bypass for highly privileged administrative users. Given the nature of the vulnerability, an attacker who gains access to a scoped API key belonging to a super-admin can effectively compromise the entire administrative infrastructure of the Grav CMS instance.

## Recommendation

- Upgrade the grav-plugin-api plugin to version 1.0.18 or higher across all production Grav CMS instances.
- Audit existing API key scopes and permissions for all accounts with administrative privileges to identify keys that may have been misused.
- Review web server access logs for anomalous activity directed at user-management API endpoints, specifically searching for unauthorized requests originating from existing API keys.
- Revoke any API keys suspected of being used for unauthorized administrative changes.
