---
title: TeamPCP Compromise of KICS GitHub Action Supply Chain
slug: 2024-06-07-teampcp-kics-supply-chain
description: TeamPCP conducted a supply chain attack compromising the KICS GitHub Action, impacting users who integrated the compromised version into their CI/CD pipelines.
date: "2026-03-23T19:20:57Z"
type: coverage
types:
  - coverage
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - github-actions
  - ci/cd
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data From Local System
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s1qnim/kics_github_action_compromised_teampcp_supply/
  - https://www.wiz.io/blog/teampcp-attack-kics-github-action
rules:
  - title: Detect Script Execution in GitHub Actions Workflow
    description: Detects execution of potentially malicious scripts (e.g., bash, python, powershell) within GitHub Actions workflow jobs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Network Connection from GitHub Actions Runner
    description: Detects outbound network connections initiated from the GitHub Actions runner to suspicious or unknown IP addresses or domains.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

On March 23, 2026, Wiz.io reported a supply chain attack targeting the KICS (Keeping Infrastructure Configuration Secure) GitHub Action. The threat actor, identified as TeamPCP, successfully compromised the KICS GitHub Action, potentially impacting numerous organizations utilizing the action in their CI/CD pipelines. This incident highlights the risks associated with supply chain dependencies and the potential for malicious actors to inject malicious code into widely used software components. The KICS GitHub Action is used to scan infrastructure-as-code (IaC) files for security vulnerabilities, making its compromise a significant security concern. Organizations that used the compromised version of the action may have had their secrets exfiltrated, or their infrastructure configurations altered.

## Attack Chain

Due to the limited information, the attack chain below is based on a typical supply chain compromise scenario:

1.  TeamPCP gains unauthorized access to the KICS GitHub Action repository or its build process.
2.  The attacker injects malicious code into the KICS GitHub Action. This code could be designed to exfiltrate sensitive information, modify infrastructure configurations, or establish a backdoor.
3.  A new version of the KICS GitHub Action, containing the malicious code, is released and made available on the GitHub Marketplace.
4.  Organizations using the KICS GitHub Action automatically update to the compromised version through their CI/CD pipelines.
5.  The malicious code executes within the CI/CD environments of victim organizations, potentially gaining access to environment variables, secrets, and other sensitive data.
6.  The malicious code exfiltrates collected data to attacker-controlled infrastructure.
7.  The attacker uses the exfiltrated data to further compromise the victim's infrastructure or gain unauthorized access to their systems.

## Impact

The compromise of the KICS GitHub Action represents a significant supply chain risk. Organizations utilizing the compromised action in their CI/CD pipelines could have experienced exfiltration of sensitive data, including API keys, credentials, and infrastructure configurations. Successful exploitation could lead to unauthorized access to cloud resources, data breaches, and disruption of services. While the exact number of affected organizations remains unclear, the widespread use of KICS suggests a potentially large impact.

## Recommendation

*   Investigate CI/CD pipeline logs for usage of the compromised KICS GitHub Action version (refer to Overview).
*   Audit GitHub Action dependencies in CI/CD pipelines to identify and remove any unauthorized or suspicious actions (refer to Overview).
*   Monitor network traffic originating from CI/CD environments for connections to unusual or malicious destinations (based on potential exfiltration in Attack Chain).
*   Implement stricter access controls and monitoring for GitHub Action repositories and build processes to prevent future supply chain attacks (refer to Overview).
*   Deploy the Sigma rule detecting suspicious script execution within GitHub Action workflows to identify potential malicious activity (see rule below).
