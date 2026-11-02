---
brief_id: brief-2026-11-02-github-sso-recovery-code-monitoring
event_id: brief-2026-11-02-github-sso-recovery-code-monitoring
revision: 1
activity_at: "2026-11-02T15:09:08Z"
title: GitHub Enterprise and Organization SSO Recovery Code Activity
slug: 2026-11-github-sso-recovery-code-monitoring
description: GitHub SSO recovery codes act as break-glass credentials bypassing IdP-enforced MFA, and their unauthorized generation, access, or usage indicates potential credential access or persistence attempts.
date: "2026-11-02T15:09:08Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - cloud
  - saas
  - credential-access
  - persistence
vendors:
  - GitHub
products:
  - GitHub (Enterprise/Organization)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Detects viewing, downloading, printing, generating, or using GitHub enterprise or organization SSO recovery codes.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: These codes bypass the IdP and are break-glass credentials.
    confidence_band: high
references:
  - https://docs.github.com/en/enterprise-cloud@latest/admin/identity-and-access-management/managing-recovery-codes-for-your-enterprise/downloading-your-enterprise-accounts-single-sign-on-recovery-codes
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/credential_access_github_recovery_codes_activity.toml
action_plan:
  priority: elevated
  owners:
    - SOC
  hunt_leads:
    - lead: Identify anomalous GitHub recovery code lifecycle events in audit logs
      technique_id: T1552
      data_needed:
        - GitHub audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Recovery-code events are rare. Download/view/print/generate often precede an SSO bypass.
  mitigation_plan:
    - priority: immediate
      action: 'Implement alerting on GitHub audit log actions: business.recovery_codes_*, org.recovery_codes_*'
      owner: Detection Engineering
      addresses: Credential Access via SSO bypass
      evidence: Monitoring these events allows security teams to detect potential account takeovers.
---

GitHub provides recovery codes for enterprise and organization SSO as a contingency for IdP access loss. Because these codes bypass external identity providers and MFA, they represent high-value targets for adversaries seeking to establish persistence or perform account takeover. Organizations should audit all actions related to these credentials, including generation, downloading, viewing, and usage, to identify anomalous administrative behavior.

## Impact
Unauthorized access to recovery codes allows an attacker to bypass federated authentication and MFA, enabling persistent, unauthenticated access to the GitHub enterprise or organization environment.

## Recommendation
- Implement monitoring for GitHub audit logs specifically filtering for recovery code lifecycle events (download, generate, print, view, use, and failure).
- Enforce dual-control procedures for the management of recovery codes, ensuring that any lifecycle event is tied to an authorized disaster recovery process.
- Rotate recovery codes immediately if an unauthorized generation or viewing event is identified.
- Review SSO configuration and force re-authentication of enterprise owners following any confirmed compromise of recovery credentials.
