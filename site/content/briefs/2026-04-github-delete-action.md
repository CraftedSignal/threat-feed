---
title: Detection of Github Delete Actions in Audit Logs
slug: 2026-04-github-delete-action
description: This brief focuses on detecting deletion actions within GitHub audit logs, specifically targeting the deletion of codespaces, environments, projects, and repositories, potentially indicating malicious activity or insider threats.
date: "2026-04-28T10:00:00Z"
severities:
  - medium
tags:
  - github
  - audit
  - data-loss
  - impact
vendors:
  - Github
products:
  - Github
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#audit-log-actions
  - https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events#codespaces
rules:
  - title: Github Delete Action Invoked
    description: Detects delete action in the Github audit logs for codespaces, environment, project and repo.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - impact
    techniques:
      - T1213.003
    data_sources:
      - github
      - audit
  - title: Github Repository Destroy Action
    description: Detects the destruction of a repository in Github audit logs.
    platform: sigma
    severity: high
    tactics:
      - collection
      - impact
    techniques:
      - T1213.003
    data_sources:
      - github
      - audit
rules_count: 2
---

This detection strategy focuses on identifying potentially malicious or unauthorized deletion activities within a GitHub organization. The detections hinge on monitoring GitHub audit logs for specific actions related to the deletion of critical resources. This includes actions such as deleting codespaces (`codespaces.destroy`), deleting environments (`environment.delete`), deleting projects (`project.delete`), and destroying repositories (`repo.destroy`). This activity is important for…
