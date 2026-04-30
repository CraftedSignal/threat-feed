---
title: GitHub Self-Hosted Runner Configuration Changes Detected
slug: 2024-01-github-runner-changes
description: Detection of changes to self-hosted runner configurations in GitHub environments can indicate potential impact, discovery, collection, persistence, privilege escalation, initial access, or stealth activities.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - github
  - self-hosted-runner
  - audit-log
  - devops
  - supply-chain
vendors:
  - GitHub
products:
  - GitHub Actions
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1526
    technique_name: Cloud Instance Backdoor
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1213
    technique_name: Data from Information Repositories
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1526
    technique_name: Cloud Instance Backdoor
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1526
    technique_name: Cloud Instance Backdoor
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1526
    technique_name: Cloud Instance Backdoor
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1526
    technique_name: Cloud Instance Backdoor
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners#about-self-hosted-runners
  - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#search-based-on-operation
rules:
  - title: GitHub Self-Hosted Runner Creation Detected
    description: Detects the registration of new self-hosted runners in a GitHub repository, which could indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1526
    data_sources:
      - github
      - audit
  - title: GitHub Self-Hosted Runner Removal Detected
    description: Detects the removal of self-hosted runners from a GitHub repository or organization, which could indicate malicious activity or an attempt to cover tracks.
    platform: sigma
    severity: low
    tactics:
      - impact
      - stealth
    techniques:
      - T1526
    data_sources:
      - github
      - audit
  - title: GitHub Self-Hosted Runner Group Changes Detected
    description: Detects changes to runner groups such as creation, removal, or modification.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1526
    data_sources:
      - github
      - audit
rules_count: 3
---

This threat brief focuses on detecting changes to self-hosted runner configurations within GitHub environments. Self-hosted runners are systems deployed and managed by users to execute jobs from GitHub Actions, providing flexibility and control over the execution environment. Monitoring these runners is crucial because unauthorized modifications can lead to various malicious activities, including data collection, persistence, privilege escalation, or even initial access. The rule provided detects such changes based on audit logs, requiring administrators to validate the changes through the GitHub UI for complete context. Detecting these modifications early can help prevent or mitigate potential security breaches.

## Attack Chain

1.  An attacker gains unauthorized access to a GitHub organization or repository with permissions to manage self-hosted runners. This could be achieved through compromised credentials (T1078.004) or exploiting a vulnerability.
2.  The attacker modifies the configuration of an existing self-hosted runner group or creates a new runner group (org.runner_group_created).
3.  The attacker adds or removes runners from a runner group (org.runner_group_runners_added, org.runner_group_runner_removed, org.runner_group_updated).
4.  Alternatively, the attacker registers a new self-hosted runner within the environment (repo.register_self_hosted_runner).
5.  The attacker removes an existing self-hosted runner from the environment (repo.remove_self_hosted_runner, org.remove_self_hosted_runner).
6.  The attacker uses the compromised runner or runner group to execute malicious code within the GitHub Actions workflow, potentially collecting sensitive data or escalating privileges.
7.  The attacker leverages the compromised runner to establish persistence within the GitHub environment, ensuring continued access.
8.  The attacker exploits the compromised runner to gain initial access to other systems or networks connected to the GitHub environment.

## Impact

Compromised self-hosted runners can lead to a range of impacts, including data exfiltration, code injection, and privilege escalation within the targeted GitHub environment. Successful attacks could result in unauthorized access to sensitive repositories, modification of code, or deployment of malicious software. The impact can vary depending on the scope of the compromised runner and the permissions associated with it. The effects could extend beyond the GitHub environment if the compromised runner has access to other systems or networks.

## Recommendation

*   Enable the audit log streaming feature in GitHub to capture events related to self-hosted runner modifications, as required by the logsource definition.
*   Deploy the Sigma rule "Github Self Hosted Runner Changes Detected" to your SIEM and tune for your specific environment to detect suspicious configuration changes.
*   Regularly review the audit logs in the GitHub UI to validate any detected changes to self-hosted runners and runner groups to ensure legitimate modifications.
*   Implement strict access control policies for managing self-hosted runners, limiting permissions to only authorized personnel.
