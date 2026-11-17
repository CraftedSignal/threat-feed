---
brief_id: brief-2026-11-17-github-repo-creation
event_id: brief-2026-11-17-github-repo-creation
revision: 1
activity_at: "2026-11-17T14:58:25Z"
title: 'GitHub: Repository creation by non-bot actors'
slug: 2026-11-github-repo-creation
description: The creation of a GitHub repository by a non-bot actor can indicate unauthorized infrastructure setup, data staging, or the use of a compromised GitHub account.
date: "2026-11-17T14:58:25Z"
type: advisory
types:
  - advisory
severities:
  - low
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
  - github
  - threat-detection
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1648
    technique_name: Serverless Execution
    evidence: This rule monitors repository creation as a potential indicator of unauthorized infrastructure setup.
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1583
    technique_name: Acquire Infrastructure
    subtechnique_id: T1583.006
    subtechnique_name: Web Services
    evidence: Unauthorized repository creation can indicate misuse of a compromised GitHub account to stage infrastructure.
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/execution_github_repo_created.toml
  - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization
rules:
  - title: GitHub Repo Created
    description: Identifies the creation of a GitHub repository by a non-bot actor. Unexpected repository creation can indicate unauthorized infrastructure setup, data staging, or misuse of a compromised GitHub account.
    platform: sigma
    severity: low
    data_sources:
      - configuration
      - github
      - audit
rules_count: 1
---

## Overview
GitHub audit logs can be monitored to identify the creation of new repositories by non-bot actors. While repository creation is a routine development activity, unexpected or unauthorized creation may be a sign of account compromise, the development of malicious infrastructure, or the staging of sensitive data. Defenders should evaluate the actor, organization context, and repository properties when this event occurs.

## Attack Chain
This activity is associated with Resource Development (T1583.006) and Execution (T1648).

## Impact
Unauthorized repository creation may support unauthorized code hosting, data staging, persistence, or resource development after an account is compromised.

## Recommendation
- Monitor GitHub audit logs (data_stream.dataset: "github.audit") for events where event.action is "repo.create" and github.actor_is_bot is false.
- When an alert triggers, investigate the actor's recent activity, including permission changes, webhooks, secrets, and repository visibility settings.
- Validate the business purpose of the repository with the identified owner or organization administrator.
