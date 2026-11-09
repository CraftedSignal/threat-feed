---
brief_id: brief-2026-11-09-vigilant-wp-auth-bypass
event_id: brief-2026-11-09-vigilant-wp-auth-bypass
revision: 1
activity_at: "2026-11-09T17:49:55Z"
title: 'The Vigilant WordPress plugin: Authentication bypass via 2FA enforcement failure (CVE-2026-123091)'
slug: 2026-11-vigilant-wp-auth-bypass
description: The Vigilant WordPress plugin before version 2.11.0 fails to enforce two-factor authentication on non-default login forms, allowing credentialed attackers to bypass 2FA.
date: "2026-11-09T17:49:55Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of plugin versioning
cpes:
  - cpe:2.3:a:the_vigilant:the_vigilant:*:*:*:*:*:wordpress:*:*
vendors:
  - The Vigilant
products:
  - The Vigilant WordPress plugin (< 2.11.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.002
    subtechnique_name: Domain Accounts
    evidence: The Vigilant WordPress plugin before 2.11.0 does not enforce its two-factor authentication on login forms other than the default WordPress one, allowing an attacker who knows a user's password to skip the second factor and log in as that user.
    confidence_band: high
cves:
  - id: CVE-2026-123091
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123091
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade The Vigilant WordPress plugin to 2.11.0 or later
      owner: IT Operations
      due: 24h
      evidence: Vulnerability addressed in version 2.11.0
  hunt_leads:
    - lead: Hunt for authentication attempts originating from non-standard login paths (e.g., custom themes or plugin-specific login pages) that do not trigger 2FA audit logs
      technique_id: T1078.002
      data_needed:
        - WordPress access logs
        - Plugin-specific authentication logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The Vigilant plugin fails to enforce 2FA on login forms other than the default one
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 2.11.0
      owner: IT Operations
      addresses: CVE-2026-123091
      evidence: Plugin maintainer patch release
---

The Vigilant WordPress plugin for WordPress contains an authentication bypass vulnerability. Versions prior to 2.11.0 fail to enforce the configured two-factor authentication (2FA) mechanism when users authenticate via non-default WordPress login forms. An attacker in possession of a valid username and password can bypass the 2FA requirement to gain unauthorized access to the application.

## Impact

Successful exploitation allows an attacker to bypass multi-factor authentication, significantly increasing the risk of account takeover for both administrative and standard user accounts.

## Recommendation

* Update "The Vigilant" WordPress plugin to version 2.11.0 or later immediately to enforce 2FA consistency across all login entry points.
* Audit WordPress login logs for anomalous authentication events originating from non-standard login endpoints.
