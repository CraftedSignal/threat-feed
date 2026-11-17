---
brief_id: brief-2026-11-17-github-outside-collaborator
event_id: brief-2026-11-17-github-outside-collaborator
revision: 1
activity_at: "2026-11-17T14:58:57Z"
title: GitHub Outside Collaborator Added to Repository
slug: 2026-11-github-outside-collaborator
description: This rule identifies when an outside collaborator is added to a GitHub repository, a technique that can be used to maintain persistent access after an account or token compromise by bypassing organization SSO and team-based access reviews.
date: "2026-11-17T14:58:57Z"
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
  likelihood: likely
tags:
  - 'Domain: Cloud'
  - 'Domain: SaaS'
  - 'Platform: GitHub'
  - 'Tactic: Persistence'
  - 'Data Source: Github'
  - 'Data Source: GitHub Audit Logs'
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    subtechnique_id: T1098.003
    subtechnique_name: Additional Cloud Roles
    evidence: An attacker who has compromised an account or token can add a collaborator they control to retain access to private source code after the original credential is revoked, bypassing organization SSO and team-based review.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/persistence_github_outside_collaborator_added.toml
  - https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators/adding-outside-collaborators-to-repositories-in-your-organization
  - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization
rules:
  - title: GitHub Outside Collaborator Added to Repository
    description: Identifies an outside collaborator being added to a GitHub repository. An outside collaborator is an individual account that is not a member of the organization but is granted direct access to one or more repositories.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - github
rules_count: 1
---

## Overview
Outside collaborators are individual accounts granted direct repository access without being organization members. Attackers who have compromised an account or a programmatic token (such as a classic or fine-grained PAT) can add a collaborator they control to retain access to private source code, bypassing organization-level security controls like SSO and team-based review. This action is distinct from adding an organization member.

## Attack Chain
An attacker who gains unauthorized access to a GitHub account or token uses the `org.add_outside_collaborator` audit event to grant repository access to an account they control, facilitating persistence that persists after the original compromised credential is revoked.

## Impact
Unauthorized outside collaborators can access, clone, and download private repository contents, potentially leading to unauthorized data access.

## Recommendation
- Monitor the `org.add_outside_collaborator` audit event. 
- Identify the actor using `user.name` and `github.actor_ip`, and review the `github.permission` granted.
- Determine if the grant was made interactively via the web UI or programmatically using a token (`github.hashed_token`, `github.programmatic_access_type`); token-based additions warrant higher urgency.
- Validate that the added account is authorized, as outside collaborators bypass standard organization security policies.
