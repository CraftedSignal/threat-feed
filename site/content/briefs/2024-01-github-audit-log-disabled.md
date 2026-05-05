---
title: GitHub Enterprise Audit Log Streaming Disabled
slug: 2024-01-github-audit-log-disabled
description: An attacker disables audit log event streaming in GitHub Enterprise to evade detection by preventing security monitoring platforms from receiving audit events.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - github
  - audit-logging
  - defense-evasion
vendors:
  - GitHub
products:
  - github.com
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk
rules:
  - title: GitHub Enterprise Disable Audit Log Event Stream
    description: Detects when a user disables audit log event streaming in GitHub Enterprise, potentially indicating an attempt to evade detection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise Audit Log Streaming Configuration Change
    description: Detects changes to the Audit Log Streaming configuration.
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

Attackers may disable audit log event streaming in GitHub Enterprise to prevent their malicious activities from being logged and detected. This involves modifying GitHub Enterprise audit log configurations to stop the flow of audit events to security monitoring platforms like Splunk. This action allows adversaries to operate undetected within the GitHub environment, making it difficult for security teams to identify and respond to security incidents. This is especially concerning as it can precede other attacks where adversaries aim to operate without being noticed. The impact of successful disabling of audit logging can be significant, as it creates a blind spot for security monitoring and incident response capabilities.

## Attack Chain

1.  The attacker gains unauthorized access to a GitHub Enterprise account with administrative privileges.
2.  The attacker navigates to the GitHub Enterprise settings related to audit log streaming.
3.  The attacker identifies the configuration responsible for streaming audit logs to external security monitoring platforms.
4.  The attacker modifies the audit log streaming configuration to disable the active stream. This corresponds to the `audit_log_streaming.destroy` action.
5.  The system ceases to send audit events to the configured security monitoring platform, such as a Splunk HTTP Event Collector.
6.  The attacker proceeds with malicious activities within the GitHub Enterprise environment, knowing that their actions are less likely to be detected.
7.  Security monitoring platforms no longer receive real-time audit data, hindering the ability to detect suspicious activities.
8.  The attacker achieves their objective, whether it is exfiltration of data, modification of code, or other malicious actions, without immediate detection.

## Impact

Disabling audit log event streaming in GitHub Enterprise results in a loss of visibility into user actions, configuration changes, and security events. This can allow attackers to perform malicious activities without detection, leading to potential data breaches, code compromises, and other security incidents. The severity is high because it directly impacts an organization's ability to monitor and respond to threats within their GitHub Enterprise environment, creating a significant blind spot in security monitoring and incident response capabilities.

## Recommendation

*   Deploy the Sigma rule `GitHub Enterprise Disable Audit Log Event Stream` to your SIEM and tune for your environment to detect disabling of audit log streaming.
*   Investigate any detected instances of `audit_log_streaming.destroy` actions in GitHub Enterprise audit logs for potentially malicious intent.
*   Implement multi-factor authentication (MFA) to protect GitHub Enterprise accounts from unauthorized access, mitigating initial access vectors.
*   Review GitHub Enterprise audit logs regularly to ensure that audit log streaming is properly configured and functioning as expected, as described in the GitHub Enterprise documentation.
