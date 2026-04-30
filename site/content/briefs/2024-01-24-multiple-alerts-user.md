---
title: Multiple Alerts Involving a User Detection
slug: 2024-01-24-multiple-alerts-user
description: This rule identifies when multiple different alerts involving the same user are triggered, which could indicate a compromised user account and requires further investigation.
date: "2024-01-24T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - threat-detection
  - higher-order-rule
vendors:
  - Elastic
products:
  - Elastic Security
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/multiple_alerts_involving_user.toml
rules:
  - title: Multiple Alerts Involving a User
    description: Detects when a user triggers multiple distinct alerts, potentially indicating a compromised account.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
      - discovery
      - privilege_escalation
    data_sources:
      - alert
      - elastic
  - title: Multiple High-Risk Alerts for Single User
    description: Detects multiple high-risk alerts associated with a single user, indicating a potential compromise or insider threat.
    platform: sigma
    severity: high
    tactics:
      - insider_threat
      - privilege_escalation
    data_sources:
      - alert
      - elastic
rules_count: 2
---

This detection rule, sourced from Elastic's detection ruleset, is designed to identify potential user account compromises by aggregating and analyzing existing alert data. The rule focuses on scenarios where a single user triggers multiple distinct alerts, suggesting a higher likelihood of malicious activity. By excluding low-severity alerts and known system accounts, the rule aims to minimize false positives and prioritize investigations. This approach is particularly useful in environments where attackers may attempt to blend in with normal user activity while escalating privileges or moving laterally within the network. The rule utilizes esql to correlate alerts based on user ID. The rule was last updated on 2026/04/27.

## Attack Chain

1.  An attacker gains initial access to a user account, potentially through phishing, credential stuffing, or other methods.
2.  The attacker attempts to escalate privileges within the compromised account.
3.  The attacker performs reconnaissance activities, such as discovering sensitive files or network shares.
4.  The attacker attempts to move laterally to other systems within the network using the compromised credentials.
5.  The attacker accesses sensitive data, potentially exfiltrating it from the network.
6.  These actions trigger various security alerts related to privilege escalation, lateral movement, and data access.
7.  The "Multiple Alerts Involving a User" rule detects the correlation between these alerts based on the user ID.
8.  Security analysts are alerted to investigate the compromised user account and contain the potential damage.

## Impact

A successful attack leveraging a compromised user account can lead to significant data breaches, financial losses, and reputational damage. The impact can range from unauthorized access to sensitive data to the complete takeover of critical systems. By identifying compromised user accounts early, organizations can mitigate the potential damage and prevent further escalation of the attack. This detection rule helps prioritize investigations and ensures that security analysts focus on the most critical threats.

## Recommendation

*   Deploy the Sigma rule `Multiple Alerts Involving a User` to your SIEM to detect potential user account compromises based on correlated alerts.
*   Enable audit logging on systems to capture user activity and generate alerts for suspicious actions.
*   Review and tune the threshold values (e.g., distinct alert count) in the Sigma rule to align with your environment and risk tolerance.
*   Use the `Resources: Investigation Guide` tag to access guidance on investigating triggered alerts and identifying compromised user accounts.
*   Implement role-based access control (RBAC) to minimize the impact of compromised accounts by limiting access to sensitive resources.
