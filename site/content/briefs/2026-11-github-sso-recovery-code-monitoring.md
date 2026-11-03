---
brief_id: brief-2026-11-02-github-sso-recovery-code-monitoring
event_id: brief-2026-11-02-github-sso-recovery-code-monitoring
revision: 3
activity_at: "2026-11-03T15:32:00Z"
revision_history:
  - revision: 2
    at: "2026-11-02T21:10:58Z"
    checksum: sha256:2da91e9d99592263f0dd595f9806566a5903b623c5b6e2f1c4d0b02c366ee2d4
    summary: added coverage for github.com
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - qa_status
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/credential_access_github_secret_scanning_alert_created.toml
  - revision: 3
    at: "2026-11-03T15:32:00Z"
    checksum: sha256:0badf784373a63f06479d671fe09ef5b5231798eac468f7868b9e947b2378ae6
    summary: added coverage for github.com
    changed_fields:
      - action_plan
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/defense_evasion_github_pat_access_restriction_disabled.toml
title: GitHub Enterprise and Organization SSO Recovery Code Activity
slug: 2026-11-github-sso-recovery-code-monitoring
description: GitHub SSO recovery codes act as break-glass credentials bypassing IdP-enforced MFA, and their unauthorized generation, access, or usage indicates potential credential access or persistence attempts.
date: "2026-11-02T15:09:08Z"
lastmod: "2026-11-03T15:30:56Z"
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
qa_status:
  verdict: pass
  validation_status: Source-based detection logic verified against Elastic detection rule schema.
tags:
  - cloud
  - saas
  - credential-access
  - persistence
  - github
  - defense-evasion
vendors:
  - GitHub
products:
  - GitHub (Enterprise/Organization)
  - github.com
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
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Detects GitHub secret scanning creating an alert for a secret that it has determined is publicly leaked ("github.publicly_leaked == true").
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Disable or Modify Tools
    evidence: Following an account takeover, an adversary may disable this restriction so that a leaked or attacker-created PAT regains access to organization data.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
    evidence: Once disabled, any member's PAT can access private repositories again without owner enforcement.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Establishing token-based persistence and a data-exfiltration path, making this a high-impact change to the organization's programmatic-access controls.
    confidence_band: high
references:
  - https://docs.github.com/en/enterprise-cloud@latest/admin/identity-and-access-management/managing-recovery-codes-for-your-enterprise/downloading-your-enterprise-accounts-single-sign-on-recovery-codes
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/credential_access_github_recovery_codes_activity.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/credential_access_github_secret_scanning_alert_created.toml
  - https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/defense_evasion_github_pat_access_restriction_disabled.toml
  - https://github.blog/security/application-security/introducing-fine-grained-personal-access-tokens-for-github/
  - https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Implement automated alert for GitHub audit logs where secret_scanning_alert.create event has github.publicly_leaked equal to true.
      owner: Detection Engineering
      due: 24h
      evidence: GitHub audit logs provide this signal via the secret_scanning_alert.create event.
    - action: Deploy alerting for the GitHub audit event personal_access_token.access_restriction_disabled
      owner: Detection Engineering
      due: 48h
      evidence: Event action documented as high-impact change to programmatic-access controls.
  hunt_leads:
    - lead: Identify anomalous GitHub recovery code lifecycle events in audit logs
      technique_id: T1552
      data_needed:
        - GitHub audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Recovery-code events are rare. Download/view/print/generate often precede an SSO bypass.
    - lead: Identify historical GitHub secret scanning alerts that may have been overlooked or misclassified.
      technique_id: T1552.001
      data_needed:
        - GitHub audit logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Historical logs can be searched for the same publicly_leaked flag to find past incidents that may have been missed.
    - lead: Identify organization owners who have recently disabled PAT access restrictions.
      technique_id: T1562.001
      data_needed:
        - 'GitHub Audit Logs: event.action = personal_access_token.access_restriction_disabled'
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An adversary who has taken over an owner account may disable this control.
  mitigation_plan:
    - priority: immediate
      action: 'Implement alerting on GitHub audit log actions: business.recovery_codes_*, org.recovery_codes_*'
      owner: Detection Engineering
      addresses: Credential Access via SSO bypass
      evidence: Monitoring these events allows security teams to detect potential account takeovers.
    - priority: immediate
      action: Revoke and rotate the exposed credential, and invalidate any associated sessions.
      owner: IT Operations
      addresses: Confirmed leaked credentials identified via GitHub scan.
      evidence: The publicly leaked flag indicates a confirmed credential compromise.
    - priority: immediate
      action: Enforce PAT access restrictions org-wide and audit current PAT grants.
      owner: IT Operations
      addresses: Organization-wide programmatic access policy
      evidence: Harden by enforcing PAT access restrictions org-wide.
updates:
  - at: "2026-11-02T21:10:19Z"
    level: L1
    summary: added coverage for github.com
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/credential_access_github_secret_scanning_alert_created.toml
  - at: "2026-11-03T15:30:56Z"
    level: L1
    summary: added coverage for github.com
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/defense_evasion_github_pat_access_restriction_disabled.toml
---

GitHub provides recovery codes for enterprise and organization SSO as a contingency for IdP access loss. Because these codes bypass external identity providers and MFA, they represent high-value targets for adversaries seeking to establish persistence or perform account takeover. Organizations should audit all actions related to these credentials, including generation, downloading, viewing, and usage, to identify anomalous administrative behavior.

## Impact
Unauthorized access to recovery codes allows an attacker to bypass federated authentication and MFA, enabling persistent, unauthenticated access to the GitHub enterprise or organization environment.

## Recommendation
- Implement monitoring for GitHub audit logs specifically filtering for recovery code lifecycle events (download, generate, print, view, use, and failure).
- Enforce dual-control procedures for the management of recovery codes, ensuring that any lifecycle event is tied to an authorized disaster recovery process.
- Rotate recovery codes immediately if an unauthorized generation or viewing event is identified.
- Review SSO configuration and force re-authentication of enterprise owners following any confirmed compromise of recovery credentials.
