---
title: Detection of Github Delete Actions in Audit Logs
slug: 2026-04-github-delete-action
description: This brief focuses on detecting deletion actions within GitHub audit logs, specifically targeting the deletion of codespaces, environments, projects, and repositories, potentially indicating malicious activity or insider threats.
date: "2026-04-28T10:00:00Z"
type: advisory
types:
  - advisory
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

This detection strategy focuses on identifying potentially malicious or unauthorized deletion activities within a GitHub organization. The detections hinge on monitoring GitHub audit logs for specific actions related to the deletion of critical resources. This includes actions such as deleting codespaces (`codespaces.destroy`), deleting environments (`environment.delete`), deleting projects (`project.delete`), and destroying repositories (`repo.destroy`). This activity is important for defenders because these actions can lead to data loss, service disruption, or compromise of the software development lifecycle. The detections are triggered by events recorded within the GitHub audit log, requiring audit log streaming to be enabled.

## Attack Chain

1.  **Initial Access:** An attacker gains unauthorized access to a GitHub account with sufficient privileges. This could be achieved through compromised credentials or insider access.
2.  **Privilege Escalation (Optional):** The attacker escalates privileges within the GitHub organization to gain the necessary permissions to delete resources if they don't already have them.
3.  **Reconnaissance:** The attacker identifies valuable codespaces, environments, projects, or repositories within the GitHub organization that they intend to delete.
4.  **Deletion of Codespaces:** The attacker executes the `codespaces.destroy` action, deleting a specific codespace instance, potentially disrupting development workflows.
5.  **Deletion of Environments:** The attacker executes the `environment.delete` action, removing a specific environment configuration, potentially affecting deployment processes.
6.  **Deletion of Projects:** The attacker executes the `project.delete` action, deleting a project board and its associated tasks, impacting project management.
7.  **Deletion of Repositories:** The attacker executes the `repo.destroy` action, permanently deleting a repository, leading to code loss and potential service disruption.
8.  **Impact:** The deletion of critical resources disrupts development workflows, causes data loss, and potentially compromises the software development lifecycle.

## Impact

Successful execution of these actions can lead to significant disruption of software development workflows, data loss, and potential compromise of the software supply chain. The number of affected resources and the severity of the impact depend on the scope of the attacker's access and the criticality of the deleted resources.

## Recommendation

*   Enable GitHub audit log streaming to capture the necessary events for detection (reference: logsource definition).
*   Deploy the provided Sigma rule to detect `codespaces.destroy`, `environment.delete`, `project.delete`, and `repo.destroy` actions in the GitHub audit logs, and tune for your environment (reference: rules).
*   Investigate any alerts triggered by the Sigma rule to determine the legitimacy of the deletion activity and the actor involved (reference: rules, falsepositives).
*   Validate the "actor" field in the audit logs to ensure the deletion activity is performed by an authorized user (reference: falsepositives).
