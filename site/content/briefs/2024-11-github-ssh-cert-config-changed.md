---
title: GitHub SSH Certificate Configuration Changed
slug: 2024-11-github-ssh-cert-config-changed
description: Attackers can modify SSH certificate configurations in GitHub organizations to gain unauthorized access, persist in the environment, escalate privileges, and operate stealthily.
date: "2024-11-02T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - github
  - ssh
  - certificate
  - initial-access
  - persistence
  - privilege-escalation
  - stealth
  - t1078.004
vendors:
  - Github
products:
  - Github
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-git-access-to-your-organizations-repositories/about-ssh-certificate-authorities
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise#ssh_certificate_authority
rules:
  - title: GitHub SSH Certificate Authority Created
    description: Detects the creation of a new SSH certificate authority in GitHub.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - github
      - audit
  - title: GitHub SSH Certificate Requirement Disabled
    description: Detects when the requirement for members to use SSH certificates is disabled.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - github
      - audit
rules_count: 2
---

Attackers can abuse SSH certificate authorities in GitHub to gain unauthorized access to repositories. By creating or disabling SSH certificate requirements, attackers can bypass existing security controls and establish persistent access. This activity is logged in the GitHub audit logs, specifically when `ssh_certificate_authority.create` or `ssh_certificate_requirement.disable` actions are performed. Successful exploitation allows attackers to commit malicious code, steal sensitive data, or disrupt development workflows, impacting the integrity and confidentiality of the organization's resources. The GitHub audit log streaming feature must be enabled to detect this activity.

## Attack Chain

1.  **Initial Compromise:** An attacker gains initial access to a GitHub organization, potentially through compromised credentials or social engineering.
2.  **Privilege Escalation:** The attacker escalates their privileges to an organizational role capable of managing SSH certificate authorities.
3.  **SSH Certificate Authority Creation:** The attacker creates a new SSH certificate authority within the GitHub organization (`ssh_certificate_authority.create`).
4.  **Disable SSH Certificate Requirement:** Alternatively, the attacker disables the requirement for members to use SSH certificates to access organization resources (`ssh_certificate_requirement.disable`). This action allows attackers to bypass security controls that enforce SSH certificate usage.
5.  **Unauthorized Access:** The attacker utilizes the newly created SSH certificate authority or the disabled requirement to access repositories without proper authorization.
6.  **Lateral Movement:** The attacker moves laterally within the GitHub organization, accessing additional repositories and resources.
7.  **Data Exfiltration/Malicious Code Injection:** The attacker exfiltrates sensitive data or injects malicious code into the organization's repositories.
8.  **Persistence:** The attacker maintains persistent access by using the created SSH certificate authority or the disabled requirement for future unauthorized activities.

## Impact

Successful modification of SSH certificate configurations in GitHub can lead to unauthorized code commits, data breaches, and supply chain attacks. This could result in financial losses, reputational damage, and legal repercussions for the affected organization. The number of affected repositories and the severity of the impact depend on the scope of the attacker's access and the sensitivity of the compromised data.

## Recommendation

*   Enable the GitHub audit log streaming feature to capture SSH certificate configuration changes (logsource: github, service: audit, definition).
*   Deploy the provided Sigma rule to detect `ssh_certificate_authority.create` or `ssh_certificate_requirement.disable` events in the GitHub audit logs (rule: Github SSH Certificate Configuration Changed).
*   Regularly review GitHub audit logs for any unauthorized modifications to SSH certificate configurations.
