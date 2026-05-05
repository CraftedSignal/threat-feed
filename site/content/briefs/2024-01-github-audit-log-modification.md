---
title: GitHub Enterprise Audit Log Event Stream Modification
slug: 2024-01-github-audit-log-modification
description: An attacker modifies or disables audit log event streaming in GitHub Enterprise to evade detection by preventing security monitoring platforms from receiving audit events.
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
  - supply-chain
vendors:
  - GitHub
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - github.com
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk
rules:
  - title: GitHub Enterprise Audit Log Stream Modified
    description: Detects modifications to the GitHub Enterprise audit log event stream.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise Audit Log Streaming Update (Splunk)
    description: Detects modifications to the GitHub Enterprise audit log event stream using Splunk logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - windows
rules_count: 2
---

This threat brief focuses on the modification or disabling of audit log event streaming within GitHub Enterprise. Attackers may target this functionality to evade detection by disrupting the flow of audit events to security monitoring platforms. The activity is logged in GitHub Enterprise audit logs as `audit_log_streaming.update`. Detecting these modifications is crucial for security operations centers (SOCs) because it can signal an imminent or ongoing attack where adversaries are attempting to cover their tracks. A successful attack could lead to a significant loss of visibility into user actions, configuration changes, and security events within the GitHub Enterprise environment, allowing attackers to operate undetected and potentially causing severe damage.

## Attack Chain

1.  The attacker gains initial access to a GitHub Enterprise account with administrative privileges.
2.  The attacker authenticates to the GitHub Enterprise instance using stolen credentials or compromised API keys.
3.  The attacker navigates to the audit log streaming configuration settings within the GitHub Enterprise administrative interface.
4.  The attacker modifies the audit log streaming configuration, either disabling the stream entirely or altering the destination to a controlled or inaccessible location. This action generates an `audit_log_streaming.update` event.
5.  The attacker proceeds with other malicious activities within the GitHub Enterprise environment, such as creating rogue repositories, modifying code, or exfiltrating data.
6.  Because audit logs are no longer being streamed to the security monitoring platform, the attacker's subsequent actions go largely undetected.
7.  The attacker maintains persistence within the environment, leveraging the lack of monitoring to escalate privileges and further compromise the system.

## Impact

Successful modification of GitHub Enterprise audit log event streaming can have a severe impact. Organizations lose visibility into critical security events, user actions, and configuration changes, creating a blind spot for incident response. This can enable attackers to perform malicious activities, such as code theft, data exfiltration, or supply chain compromise, without detection. This can lead to reputational damage, financial losses, and legal repercussions.

## Recommendation

*   Enable and actively monitor GitHub Enterprise audit logs using Audit log streaming as described in the GitHub documentation to ensure continuous visibility into critical events ([https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk)).
*   Deploy the provided Sigma rule to your SIEM (Splunk) to detect modifications to the audit log event stream by monitoring for `audit_log_streaming.update` events.
*   Investigate any detected modifications to the audit log event stream to determine the actor, the scope of the changes, and any potential malicious intent by examining the `actor`, `actor_id`, and `actor_ip` fields in the logs.
