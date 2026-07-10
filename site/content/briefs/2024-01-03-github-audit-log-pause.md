---
title: GitHub Enterprise Audit Log Streaming Paused
slug: 2024-01-03-github-audit-log-pause
description: A user pausing the audit log event stream in GitHub Enterprise, potentially indicating an attempt to evade detection by disabling audit trails.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - audit-log
  - defense-evasion
  - cloud
vendors:
  - GitHub
products:
  - GitHub Enterprise
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk
rules:
  - title: GitHub Audit Log Streaming Paused
    description: Detects when a user pauses audit log event streaming in GitHub Enterprise.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - audit
      - github_enterprise
  - title: GitHub Audit Log Streaming Configuration Change
    description: Detects any changes to the audit log streaming configuration in GitHub Enterprise.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - audit
      - github_enterprise
rules_count: 2
---

This analytic identifies instances where a user pauses audit log event streaming within a GitHub Enterprise environment. Attackers might attempt to disable audit logging to conceal malicious activities. The pausing of audit logs temporarily suspends the stream of audit events to security monitoring platforms like Splunk, creating a blind spot in security visibility. This technique could be employed following a successful initial access, such as through a compromised account, and before conducting activities like code modification or data exfiltration. Detecting this activity is critical because it may precede other attacks where adversaries aim to operate undetected.

## Attack Chain

1.  Initial Access: An attacker gains unauthorized access to a GitHub Enterprise account, possibly through compromised credentials (T1195).
2.  Privilege Escalation (if needed): The attacker elevates their privileges to a level where they can modify audit log settings.
3.  Discovery: The attacker explores the GitHub Enterprise settings to locate the audit log streaming configuration.
4.  Disable Audit Log Streaming: The attacker pauses the audit log event stream via the GitHub Enterprise interface, using the "User initiated pause" reason (T1562.008).
5.  Malicious Activity: The attacker performs malicious actions within the GitHub Enterprise environment, such as modifying code, creating rogue repositories, or exfiltrating data, knowing their actions are not being logged.
6.  Persistence (Optional): The attacker may establish persistence mechanisms to maintain access for future malicious activities.
7.  Evasion: The attacker ensures that audit logs remain paused during their malicious activity to avoid detection.
8.  Impact: Data breach, intellectual property theft, or disruption of services.

## Impact

The successful pausing of audit logs leads to a temporary loss of visibility into user actions, configuration changes, and security events within the GitHub Enterprise environment. This creates a blind spot, allowing attackers to perform malicious activities undetected. The impact includes potential data breaches, intellectual property theft, or service disruptions. The severity depends on the duration of the pause and the extent of the attacker's activities during that period.

## Recommendation

*   Deploy the Sigma rule `GitHub Audit Log Streaming Paused` to detect instances of audit log streaming being paused (logsource: `github_enterprise`, category: audit).
*   Investigate any detected instances of audit log streaming being paused to determine the reason and potential impact.
*   Implement multi-factor authentication (MFA) for all GitHub Enterprise accounts to reduce the risk of compromised credentials (T1195).
*   Monitor GitHub Enterprise audit logs for unexpected configuration changes, particularly those related to security settings.
*   Review the references provided for guidance on setting up and monitoring GitHub Enterprise audit logs.
