---
title: 'CVE-2026-72829: Privilege Escalation in Grav API Plugin'
slug: 2026-08-grav-api-bypass
description: The Grav API plugin before version 1.0.13 contains a privilege escalation vulnerability where API keys with restricted 'api.users.write' scope can bypass authorization checks to grant themselves super-admin privileges.
date: "2026-08-14T14:11:37Z"
lastmod: "2026-08-14T16:12:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Grav
products:
  - Grav API plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Grav API plugin... contains an API-key scope-cap bypass in UsersController's create() and update() methods... allowing an attacker to promote their account to full administrative privileges.
    confidence_band: high
cves:
  - id: CVE-2026-72829
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72829
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72833
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Grav API plugin to 1.0.13 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends update to 1.0.13
  mitigation_plan:
    - priority: immediate
      action: Review and revoke suspicious API keys with user write permissions
      owner: SOC
      addresses: CVE-2026-72829
      evidence: Vulnerability allows elevation via api.users.write scope
updates:
  - at: "2026-08-14T16:12:08Z"
    level: L2
    summary: added coverage for Grav API plugin
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72833
---

The Grav API plugin (getgrav/grav-plugin-api) versions prior to 1.0.13 are susceptible to an API-key scope-cap bypass vulnerability located within the UsersController's create() and update() methods. The vulnerability stems from an insecure authorization check where the application enforces scope caps for 'api.users.write' but fails to validate super-privilege grants against the key's defined scopes. Instead, the application performs a direct 'isSuperAdmin()' check that inspects the 'access.api.super' attribute. By leveraging an API key with 'api.users.write' scope, an attacker can modify user records to assign super-admin privileges or group memberships that grant such access. This allows for the elevation of a limited API account to a full super-administrator, resulting in complete administrative control over the Grav instance.

## Impact

Successful exploitation allows an unprivileged or low-privileged API user to elevate their account to a super-administrator, leading to full site compromise, sensitive data exfiltration, and unauthorized configuration changes. This vulnerability carries a CVSS v3.1 base score of 9.8.

## Recommendation

- Upgrade the Grav API plugin (getgrav/grav-plugin-api) to version 1.0.13 or later immediately.
- Audit existing API keys for unexpected or unauthorized super-user privilege grants in the user access settings.
- Restrict the generation and distribution of API keys with 'api.users.write' scopes until the patch is applied.
