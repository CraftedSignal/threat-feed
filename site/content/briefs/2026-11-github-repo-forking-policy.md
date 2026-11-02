---
brief_id: brief-2026-11-02-github-repo-forking-policy
event_id: brief-2026-11-02-github-repo-forking-policy
revision: 1
activity_at: "2026-11-02T15:09:15Z"
title: 'GitHub: Unauthorized modification of private repository forking policy'
slug: 2026-11-github-repo-forking-policy
description: An attacker with compromised organization owner credentials may enable private repository forking to exfiltrate proprietary source code to personal accounts, necessitating monitoring of GitHub audit logs for organization-level configuration changes.
date: "2026-11-02T15:09:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
  - cloud-security
  - saas-security
  - configuration-monitoring
  - collection
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    subtechnique_id: T1213.003
    subtechnique_name: Code Repositories
    evidence: Allowing forks of private repositories lets code leave the organization into personal forks, which is a common collection path after an org-owner compromise.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
    evidence: Detects enabling of private repository forking on a GitHub organization.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/collection_github_private_repo_forking_enabled.toml
  - https://docs.github.com/en/organizations/managing-organization-settings/managing-the-forking-policy-for-your-organization
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify unauthorized repository forks following an organization-level policy change.
      technique_id: T1213.003
      data_needed:
        - 'GitHub audit logs: event.action == "repo.fork"'
        - 'GitHub audit logs: event.action == "private_repository_forking.enable"'
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Check whether private repos were forked afterward and to which accounts.
  mitigation_plan:
    - priority: immediate
      action: Disable private repository forking in GitHub organization settings
      owner: IT Operations
      addresses: GitHub Private Repository Forking Policy
      evidence: Disable private repository forking unless required.
---

This alert monitors for the enabling of private repository forking within a GitHub organization. Allowing forks of private repositories permits code to be copied out of the organization into personal forks, representing a high-risk collection path following an organization-owner compromise. This setting change is an indicator of potential data exfiltration.

## Impact

Enabling private repository forking increases the risk of unauthorized source code exfiltration by allowing users with access to private repositories to fork them into personal accounts outside the organization's control.

## Recommendation

* Review organization settings to ensure private repository forking is disabled unless explicitly required for inner-source development programs.
* Investigate the `user.name` and `github.actor_ip` associated with the policy change event `private_repository_forking.enable`.
* Audit for repository fork activity (`repo.fork` events) immediately following any detected policy change to identify if unauthorized copies were created.
* Transfer or delete any unauthorized forks identified during the investigation window.
