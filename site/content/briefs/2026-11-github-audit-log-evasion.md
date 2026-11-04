---
brief_id: brief-2026-11-02-github-audit-log-evasion
event_id: brief-2026-11-02-github-audit-log-evasion
revision: 2
activity_at: "2026-11-04T15:44:41Z"
revision_history:
  - revision: 2
    at: "2026-11-04T15:44:41Z"
    checksum: sha256:bc4759e51c4e0f2c361d6b6479be5ecb9d1043aca5ae52887f17e47b7496d383
    summary: added coverage for GitHub Enterprise +1 products
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/defense_evasion_github_saml_disabled.toml
title: 'GitHub Enterprise: Audit log streaming modification or destruction'
slug: 2026-11-github-audit-log-evasion
description: Adversaries with enterprise admin access may modify or delete GitHub Enterprise audit log streaming configurations to blind security monitoring or redirect logs to attacker-controlled infrastructure.
date: "2026-11-02T21:10:22Z"
lastmod: "2026-11-04T15:43:57Z"
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
tags:
  - cloud
  - saas
  - defense-evasion
  - github
  - credential-access
  - persistence
vendors:
  - GitHub
products:
  - GitHub Enterprise
  - GitHub Organizations
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    subtechnique_id: T1562.008
    subtechnique_name: Disable or Modify Cloud Logs
    evidence: Adversaries who gain enterprise admin access may change the stream sink or destroy it to stop security telemetry from reaching the SIEM.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Following an account takeover, an adversary may disable SSO to evade IdP-enforced access policies and maintain access that survives IdP-side session revocation and deprovisioning.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
    subtechnique_id: T1556.007
    subtechnique_name: Hybrid Identity
    evidence: Detects when SAML single sign-on (SSO) is disabled for a GitHub enterprise or organization.
    confidence_band: high
references:
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/defense_evasion_github_audit_log_streaming_modified.toml
  - https://docs.github.com/en/enterprise-cloud@latest/admin/identity-and-access-management/using-saml-for-enterprise-iam/configuring-saml-single-sign-on-for-your-enterprise
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/defense_evasion_github_saml_disabled.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Configure alerts for audit events business.disable_saml and org.disable_saml.
      owner: Detection Engineering
      due: 48h
      evidence: Rule detects administrative SAML disable events.
  hunt_leads:
    - lead: Monitor for unauthorized changes to GitHub Enterprise audit log streaming endpoints.
      technique_id: T1562.008
      data_needed:
        - GitHub audit logs (event.action in ["audit_log_streaming.update", "audit_log_streaming.destroy"])
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Adversaries who gain enterprise admin access may change the stream sink or destroy it to stop security telemetry from reaching the SIEM.
    - lead: 'Identify unauthorized disablement of SAML SSO by reviewing logs for event.action: business.disable_saml or org.disable_saml.'
      technique_id: T1556.007
      data_needed:
        - GitHub audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The event action specifically signifies the removal of IdP authentication enforcement.
  mitigation_plan:
    - priority: immediate
      action: Implement alerting on GitHub audit log streaming configuration changes and restrict administrative access.
      owner: IT Operations
      addresses: T1562.008
      evidence: Unauthorized modification of audit log streams results in a loss of security visibility.
    - priority: immediate
      action: Re-enable SAML SSO and mandate its use for all enterprise members.
      owner: IT Operations
      addresses: T1556.007
      evidence: Restores IdP-enforced security controls such as MFA and conditional access.
updates:
  - at: "2026-11-04T15:43:57Z"
    level: L1
    summary: added coverage for GitHub Enterprise +1 products
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/defense_evasion_github_saml_disabled.toml
---

GitHub Enterprise audit log streaming provides a durable record of enterprise events. Unauthorized modification or deletion of these streams allows attackers to evade detection by preventing audit logs from reaching the configured SIEM destination or by hijacking the data stream. This activity is considered a significant defense evasion technique.

## Impact
Unauthorized modification of audit log streams results in a loss of security visibility. If the production SIEM destination is deleted or reconfigured to an untrusted endpoint, security operations teams will lose the ability to detect subsequent malicious activity within the GitHub environment.

## Recommendation
- Implement monitoring for `audit_log_streaming.update` and `audit_log_streaming.destroy` events in GitHub Enterprise audit logs.
- Establish a process to audit current GitHub Enterprise streaming configurations against known-good baselines.
- Review credentials of all enterprise owners to ensure minimal privilege and verify that MFA is enforced for all administrative access.
- If a production stream is destroyed, immediately verify the integrity of the remaining logs and initiate an incident response procedure to rotate credentials and investigate for further unauthorized access.
