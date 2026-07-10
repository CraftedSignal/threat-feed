---
title: GitHub Enterprise Self-Hosted Runner Creation
slug: 2024-01-03-github-enterprise-self-hosted-runner
description: Anomalous creation of self-hosted runners in GitHub Enterprise indicates potential attacker activity to execute malicious code, access sensitive data, or pivot to other systems via compromised runners.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - supply-chain
  - self-hosted-runner
  - defense-evasion
  - initial-access
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
  - https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk
rules:
  - title: GitHub Enterprise - Self-Hosted Runner Registered
    description: Detects registration of a self-hosted runner in GitHub Enterprise.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1195
      - T1562.001
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise - Anomalous Self-Hosted Runner User Agent
    description: Detects self-hosted runner registration with unusual user agent strings.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1195
      - T1562.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat brief addresses the risk associated with the creation of self-hosted runners within GitHub Enterprise environments. Self-hosted runners, while a legitimate feature for executing workflow jobs, present a significant attack surface if compromised. Attackers can exploit these runners to execute malicious code, gain access to sensitive data, or move laterally within the network. The detection logic focuses on monitoring GitHub Enterprise audit logs for events related to the registration of new self-hosted runners at the organization or enterprise level. Defenders should closely monitor runner creation, especially by unfamiliar users or in unusual contexts. The references provided include insights into supply chain attacks and suspicious GitHub activity monitoring, underscoring the importance of this detection.

## Attack Chain

1.  **Initial Compromise:** The attacker gains initial access to a GitHub Enterprise account, possibly through credential compromise or phishing.
2.  **Privilege Escalation (Optional):** The attacker escalates privileges within the GitHub organization to create or modify settings.
3.  **Runner Registration:** The attacker registers a new self-hosted runner within the GitHub Enterprise environment using `enterprise.register_self_hosted_runner`. This could involve configuring the runner with malicious settings or allowing unauthorized access.
4.  **Workflow Manipulation:** The attacker modifies or creates GitHub Actions workflows to execute commands on the newly registered runner.
5.  **Code Execution:** The workflow executes the attacker's code on the self-hosted runner, potentially installing malware or exfiltrating data.
6.  **Lateral Movement:** From the compromised runner, the attacker pivots to other systems accessible from the runner's host environment, expanding their foothold.
7.  **Data Exfiltration:** Sensitive data is exfiltrated from the compromised systems via the runner's network connection.

## Impact

A successful compromise of a self-hosted runner can lead to significant damage, including remote code execution on the runner's host, unauthorized access to sensitive data stored in the GitHub repository or accessible from the runner's network, and lateral movement within the organization's infrastructure. The number of victims and sectors targeted would depend on the scope of access granted to the compromised runner and the sensitivity of the data within the targeted repositories. A single compromised runner could potentially impact hundreds or thousands of users and systems.

## Recommendation

*   Enable and monitor GitHub Enterprise Audit Logs, specifically for the `enterprise.register_self_hosted_runner` action, as described in the provided documentation link (https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk).
*   Implement and tune the provided Sigma rule to detect anomalous self-hosted runner creation events.
*   Investigate any detected instances of self-hosted runner creation by unfamiliar users or from unusual locations based on the actor and actor_location fields in the logs.
*   Review the permissions and access controls associated with all self-hosted runners to minimize the potential impact of a compromise.
