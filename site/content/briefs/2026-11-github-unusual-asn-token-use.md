---
brief_id: brief-2026-11-13-github-unusual-asn-token-use
event_id: brief-2026-11-13-github-unusual-asn-token-use
revision: 1
activity_at: "2026-11-13T09:45:14Z"
title: GitHub Token Clone, Push, and ZIP Access from Unusual ASN
slug: 2026-11-github-unusual-asn-token-use
description: This detection monitors for GitHub repository access via programmatic tokens originating from an autonomous system (ASN) not previously seen for a specific user, potentially indicating token theft or unauthorized access.
date: "2026-11-13T09:45:14Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic sourced directly from Elastic security engineering repository.
tags:
  - cloud
  - saas
  - github
  - collection
  - exfiltration
  - initial-access
  - defense-evasion
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    subtechnique_id: T1567.001
    subtechnique_name: Exfiltration to Code Repository
    evidence: Detects git clone, git push, or ZIP download authenticated with a classic PAT, fine-grained PAT, or OAuth access token.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    subtechnique_id: T1213.003
    subtechnique_name: Code Repositories
    evidence: Detects git clone, git push, or ZIP download authenticated with a classic PAT, fine-grained PAT, or OAuth access token.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: A token used from an unfamiliar ASN can indicate credential theft or use from an unauthorized location.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    subtechnique_id: T1550.001
    subtechnique_name: Application Access Token
    evidence: A token used from an unfamiliar ASN can indicate credential theft or use from an unauthorized location.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/exfiltration_github_token_use_from_unusual_asn.toml
  - https://securitylabs.datadoghq.com/articles/mapping-out-your-unknown-threat-hunters-guide-to-github/
  - https://github.blog/news-insights/company-news/security-alert-stolen-oauth-user-tokens/
  - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify GitHub access events (clone, push, zip download) occurring from an ASN that does not appear in the user's historical 7-day access logs.
      technique_id: T1078.004
      data_needed:
        - GitHub Audit logs
        - GeoIP/ASN resolution data
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Detects git clone, git push, or ZIP download authenticated with a classic PAT, fine-grained PAT, or OAuth access token from an autonomous system (ASN) not previously seen for that user in the last 7 days.
---

Security teams can detect potential credential abuse by monitoring for `git clone`, `git push`, or `repo.download_zip` events authenticated with classic PATs, fine-grained PATs, or OAuth access tokens originating from an unrecognized autonomous system (ASN). The detection methodology uses a 7-day look-back period for each user/ASN pair, employing ASN-level resolution to mitigate noise from IP address churn within cloud providers or ISPs.

## Impact

Unauthorized actors utilizing stolen or leaked tokens can exfiltrate sensitive source code, intellectual property, or configuration data by cloning repositories or downloading repository archives as ZIP files.

## Recommendation

- Implement monitoring for GitHub audit logs specifically filtering for `git.clone`, `git.push`, and `repo.download_zip` actions associated with programmatic access tokens.
- Investigate alerts by correlating the identified ASN and organization name against known user locations and historical access patterns.
- Revoke suspect tokens immediately if the source ASN is determined to be outside the user's operational baseline.
- Tune detection logic by adding exceptions for high-volume automated CI/CD pipelines that may span multiple cloud-provider ASNs.
