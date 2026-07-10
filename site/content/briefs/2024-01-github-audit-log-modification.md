---
title: GitHub Enterprise Audit Log Streaming Modification
slug: 2024-01-github-audit-log-modification
description: Detection of modifications or disabling of audit log event streaming in GitHub Enterprise, potentially indicating an attacker attempting to evade detection by tampering with the audit trail.
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
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk
rules:
  - title: GitHub Enterprise Audit Log Streaming Modified
    description: Detects when a user modifies or disables audit log event streaming in GitHub Enterprise.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise Audit Log Streaming Modified - User Agent
    description: Detects when a user modifies or disables audit log event streaming in GitHub Enterprise using a non-standard user agent.
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

This brief focuses on detecting unauthorized modifications to audit log event streaming within GitHub Enterprise environments. Attackers may disable or alter audit log streaming configurations to prevent their malicious activities from being logged and detected by security monitoring platforms. The threat involves tampering with the audit trail to operate undetected within the GitHub Enterprise environment. This behavior is often a precursor to more significant attacks, where adversaries aim to compromise systems and exfiltrate data without triggering alerts. The detection monitors GitHub Enterprise audit logs for configuration changes that affect the audit log streaming functionality.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to a GitHub Enterprise account with administrative privileges, potentially through compromised credentials or exploiting a vulnerability in the GitHub Enterprise platform.
2.  **Privilege Escalation (if needed):** If the initial access does not provide sufficient permissions, the attacker attempts to escalate their privileges within the GitHub Enterprise environment to gain the necessary access to modify audit log settings.
3.  **Discovery:** The attacker enumerates the current audit log streaming configuration to understand how audit logs are being collected and where they are being sent.
4.  **Disable Audit Log Streaming:** The attacker disables the audit log event streaming feature, preventing audit logs from being sent to the configured security monitoring platforms. This is achieved through the GitHub Enterprise administrative interface or API.
5.  **Modify Audit Log Streaming Configuration:** Alternatively, the attacker modifies the audit log streaming configuration to redirect audit logs to a different, attacker-controlled destination, or to filter out specific events that would reveal their malicious activity.
6.  **Evade Detection:** With audit log streaming disabled or modified, the attacker performs malicious actions within the GitHub Enterprise environment, such as creating unauthorized repositories, modifying code, or exfiltrating data, without fear of being detected by security monitoring tools.
7.  **Persistence (Optional):** The attacker may establish persistence mechanisms to maintain access to the compromised GitHub Enterprise environment and continue their malicious activities over time.
8.  **Impact:** The attacker achieves their objective, which could be data theft, intellectual property theft, or disruption of services, while remaining undetected due to the compromised audit log infrastructure.

## Impact

Successful modification or disabling of audit log streaming in GitHub Enterprise can have severe consequences. Organizations lose visibility into user actions, configuration changes, and security events within their GitHub Enterprise environment, potentially allowing attackers to perform malicious activities without detection. The impact could range from intellectual property theft and data breaches to supply chain compromise, especially given the use of GitHub in software development. A compromised audit trail creates a significant blind spot in security monitoring and incident response capabilities, increasing the dwell time of attackers within the environment.

## Recommendation

*   Deploy the Sigma rule `GitHub Enterprise Audit Log Streaming Modified` to your SIEM to detect modifications to audit log event streaming based on `action=audit_log_streaming.update`.
*   Ingest GitHub Enterprise Audit Logs using Audit log streaming as described in the GitHub documentation (reference URLs provided) using a Splunk HTTP Event Collector, as the detection relies on this log source.
*   Investigate any alerts triggered by the `GitHub Enterprise Audit Log Streaming Modified` rule, focusing on the `actor`, `actor_id`, and `actor_ip` fields to identify the user or entity responsible for the changes.
*   Implement multi-factor authentication (MFA) for all GitHub Enterprise accounts, especially those with administrative privileges, to prevent unauthorized access and modifications to audit log settings.
*   Regularly review GitHub Enterprise audit logs for any suspicious activity, including unexpected changes to audit log configurations or user behavior.
*   Monitor the `user_agent` field in the logs for unusual or unauthorized applications making changes to the audit stream.
