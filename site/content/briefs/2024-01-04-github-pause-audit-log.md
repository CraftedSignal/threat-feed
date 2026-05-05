---
title: GitHub Enterprise Audit Log Streaming Paused
slug: 2024-01-04-github-pause-audit-log
description: Detection of a user pausing audit log event streaming in GitHub Enterprise, potentially indicating an attempt to evade detection by disabling the audit trail.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - github
  - audit-log
  - defense-evasion
vendors:
  - GitHub
  - Splunk
products:
  - GitHub Enterprise
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.008
    technique_name: 'Impair Defenses: Disable or Modify Tools'
  - tactic_id: TA0011
    tactic_name: Resource Development
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk
rules:
  - title: GitHub Enterprise Pause Audit Log Event Stream
    description: Detects when a user pauses audit log event streaming in GitHub Enterprise.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise Audit Log Changes by Non-Admin
    description: Detects audit log configuration changes performed by non-administrator accounts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This analytic detects when a user pauses audit log event streaming in GitHub Enterprise. Attackers may attempt to disable audit logging to prevent their malicious activities from being logged and detected. The detection monitors GitHub Enterprise audit logs for configuration changes that temporarily suspend the audit log streaming functionality. For a SOC, identifying the pausing of audit logging is critical as it may be a precursor to other attacks where adversaries want to operate undetected during the pause window. This can lead to significant security blind spots.

## Attack Chain

1. An attacker gains unauthorized access to a GitHub Enterprise account, potentially through compromised credentials or exploiting a vulnerability.
2. The attacker authenticates to the GitHub Enterprise platform.
3. The attacker navigates to the audit log streaming configuration settings within the GitHub Enterprise administration panel.
4. The attacker initiates a pause of the audit log event stream, providing a reason for the pause (e.g., "User initiated pause").
5. The GitHub Enterprise system records this action as an `audit_log_streaming.update` event in the audit logs, including details such as the actor, timestamp, and reason.
6. While the audit log stream is paused, the attacker performs malicious activities within the GitHub Enterprise environment without generating audit logs that would be sent to external security monitoring platforms.
7. The attacker resumes the audit log stream after completing their malicious activities.
8. The attacker attempts to cover their tracks by deleting any traces of their access or changes to audit settings.

## Impact

Organizations may temporarily lose visibility into user actions, configuration changes, and security events within their GitHub Enterprise environment. Attackers can perform malicious activities without detection during the pause period, creating a temporary blind spot in security monitoring and incident response capabilities. This can lead to data breaches, intellectual property theft, or supply chain compromises.

## Recommendation

*   Ingest GitHub Enterprise logs using Audit log streaming as described in the documentation to enable detection capabilities.
*   Deploy the Sigma rule `GitHub Enterprise Pause Audit Log Event Stream` to your SIEM to detect when a user pauses audit log event streaming and tune for your environment.
*   Investigate any detected instances of audit log streaming being paused to determine if malicious activity occurred during the pause window, focusing on the `actor`, `actor_id`, `actor_ip`, `user_agent` fields.
