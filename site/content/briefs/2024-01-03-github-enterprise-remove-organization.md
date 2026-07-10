---
title: GitHub Enterprise Organization Removal
slug: 2024-01-03-github-enterprise-remove-organization
description: Detection of a user removing an organization from GitHub Enterprise, potentially indicating account compromise, insider threats, or malicious attempts to disrupt business operations by deleting critical business resources.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - cloud
  - impact
vendors:
  - GitHub
products:
  - GitHub Enterprise
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk
rules:
  - title: GitHub Enterprise Organization Removal Detection
    description: Detects when a user removes an organization from GitHub Enterprise by monitoring GitHub Enterprise audit logs for organization deletion events.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise Remove Organization via User Agent
    description: Detects when a user removes an organization from GitHub Enterprise using a suspicious user agent.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat brief focuses on the unauthorized removal of an organization within GitHub Enterprise. This action, monitored through GitHub Enterprise audit logs, can be indicative of several malicious scenarios. These include account compromise, where an attacker gains control and attempts to dismantle the organization's infrastructure; insider threats, where a malicious employee deliberately removes the organization; or a targeted attack aimed at disrupting business operations. The consequences of such an event can be severe, leading to the loss of critical source code, repositories, team structures, and access controls. The detection relies on ingesting GitHub Enterprise Audit Logs.

## Attack Chain

1.  **Initial Access:** An attacker gains unauthorized access to a GitHub Enterprise user account through compromised credentials or other means (T1195).
2.  **Privilege Escalation:** The attacker escalates privileges within the compromised account, if necessary, to gain sufficient permissions to manage organizations.
3.  **Reconnaissance:** The attacker identifies the target organization within the GitHub Enterprise instance.
4.  **Organization Removal:** The attacker initiates the process to remove the identified organization using the GitHub Enterprise interface or API.
5.  **Audit Log Trigger:** The action triggers an audit log entry within GitHub Enterprise, specifically the `business.remove_organization` event.
6.  **Data Loss/Disruption:** The removal of the organization leads to the loss of source code, repositories, team structures, and access controls associated with the organization (T1485).
7.  **Operational Impact:** Development workflows are halted, and significant effort is required to restore the organization from backups if available.

## Impact

The successful removal of a GitHub Enterprise organization can lead to severe consequences. The observed damage includes the potential loss of entire codebases, project repositories, and crucial access controls. This disruption can halt software development, lead to data breaches, and require substantial recovery efforts. The impact can range from temporary inconvenience to catastrophic data loss, depending on the size and importance of the removed organization.

## Recommendation

*   Ingest GitHub Enterprise Audit Logs using Audit log streaming as described in the documentation to enable detection of organization removal events ([https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk)).
*   Deploy the provided Sigma rule to your SIEM to detect `business.remove_organization` events in GitHub Enterprise audit logs and tune the rule for your environment.
*   Investigate any alerts triggered by the Sigma rule, focusing on the `actor`, `actor_id`, and `user_agent` fields to determine the legitimacy of the organization removal.
