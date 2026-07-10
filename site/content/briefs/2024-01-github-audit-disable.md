---
title: GitHub Enterprise Audit Log Streaming Disabled
slug: 2024-01-github-audit-disable
description: A user disabling audit log event streaming in GitHub Enterprise could indicate an attacker attempting to prevent their malicious activities from being logged and detected.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - audit-logs
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
  - title: GitHub Audit Log Streaming Disabled
    description: Detects when a user disables audit log event streaming in GitHub Enterprise.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - webserver
      - linux
  - title: GitHub Audit Log Streaming Status Check
    description: Detects failed attempts to retrieve the audit log streaming status, potentially indicating an attempt to identify if audit logging is enabled before disabling it.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat brief focuses on the disabling of audit log event streaming within GitHub Enterprise environments. The disabling of audit logs is a common technique used by attackers to evade detection by security monitoring platforms. While the exact initial access vector is unknown, once an attacker gains sufficient privileges within the GitHub Enterprise environment, they may attempt to disable audit logging to mask their subsequent actions. This activity is significant for defenders because it represents a deliberate attempt to blind security monitoring and incident response teams, potentially allowing attackers to perform malicious activities without detection. The impact could be severe as organizations lose visibility into user actions, configuration changes, and security events within their GitHub Enterprise environment.

## Attack Chain

1.  **Initial Access:** An attacker gains unauthorized access to a GitHub Enterprise account with administrative privileges.
2.  **Privilege Escalation (If Necessary):** If the initial access does not grant sufficient privileges, the attacker attempts to escalate their privileges within the GitHub Enterprise environment.
3.  **Identify Audit Log Configuration:** The attacker identifies the audit log event streaming configuration settings within GitHub Enterprise.
4.  **Disable Audit Log Streaming:** The attacker disables the audit log event streaming functionality, preventing audit events from being sent to security monitoring platforms. This is achieved by using the `audit_log_streaming.destroy` action.
5.  **Carry out Malicious Actions:** With audit logging disabled, the attacker performs unauthorized activities within the GitHub Enterprise environment, such as modifying code, creating new user accounts, or exfiltrating sensitive data.
6.  **Maintain Persistence:** The attacker establishes persistence mechanisms to maintain access to the compromised GitHub Enterprise environment.
7.  **Cover Tracks:** The attacker attempts to further cover their tracks by deleting logs or modifying system configurations.

## Impact

Disabling audit log streaming in GitHub Enterprise can have significant consequences. Organizations lose visibility into critical security events, configuration changes, and user actions within their GitHub Enterprise environment. This can enable attackers to perform malicious activities undetected, leading to data breaches, intellectual property theft, or disruption of services. The inability to monitor audit logs hinders incident response efforts and prolongs the time it takes to detect and remediate security incidents.

## Recommendation

*   Deploy the Sigma rule `GitHub Audit Log Streaming Disabled` to your SIEM to detect when a user disables audit log event streaming in GitHub Enterprise.
*   Enable and actively monitor GitHub Enterprise audit logs using Audit log streaming as described in the documentation ([https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk)).
*   Investigate any instances of `audit_log_streaming.destroy` events identified in the logs to determine if they are authorized or malicious activity.
*   Review user access controls and permissions within GitHub Enterprise to prevent unauthorized users from disabling audit log streaming.
