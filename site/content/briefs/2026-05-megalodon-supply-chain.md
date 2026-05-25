---
title: Megalodon Supply Chain Attack Infects Over 5,500 GitHub Repositories
slug: 2026-05-megalodon-supply-chain
description: The 'Megalodon' supply chain attack compromised over 5,500 GitHub repositories by injecting malicious GitHub Actions workflows designed to steal credentials, CI secrets, keys, and tokens.
date: "2026-05-25T07:42:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - github
  - github-actions
vendors:
  - GitHub
  - NPM
products:
  - GitHub Actions
  - Tiledesk
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588.006
    technique_name: 'Obtain Capabilities: Code Signing Certificates'
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588.004
    technique_name: 'Obtain Capabilities: Digital Certificates'
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.004
    technique_name: 'Application Layer Protocol: DNS'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0009
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
references:
  - https://www.securityweek.com/over-5500-github-repositories-infected-in-megalodon-supply-chain-attack/
rules:
  - title: Detect Suspicious GitHub Actions Workflow Creation
    description: Detects the creation of GitHub Actions workflows with suspicious authors, potentially indicative of the 'Megalodon' supply chain attack.
    platform: sigma
    severity: high
    tactics:
      - supply_chain_compromise
    techniques:
      - T1609
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious Commits with build-bot Author
    description: Detects commits authored by 'build-bot', a user associated with the 'Megalodon' attack. This can indicate a compromised repository.
    platform: sigma
    severity: medium
    tactics:
      - supply_chain_compromise
    techniques:
      - T1609
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The 'Megalodon' supply chain attack targeted GitHub repositories, injecting malicious GitHub Actions workflows designed to steal sensitive information. The attack, discovered by SafeDep, involved the injection of over 5,700 malicious commits within a six-hour window on May 18, 2026. These commits added or replaced workflows to exfiltrate CI environment variables, AWS/GCP/Azure credentials, SSH private keys, Docker/Kubernetes configurations, API keys, database connection strings, and various tokens. Malicious versions of the Tiledesk package, an open source live chat platform, were identified as part of the attack between May 19 and May 21. The attackers exploited GitHub's workflow dispatch feature to create dormant backdoors that could be triggered later.

## Attack Chain

1.  Attacker compromises the GitHub repository of the Tiledesk package.
2.  Malicious commits are authored by 'build-bot' and pushed to repositories on May 18, 2026, across a six-hour window.
3.  The attacker uses two payloads: one adds a new workflow, and another replaces existing workflows.
4.  The new workflow is designed to trigger on every push and pull request.
5.  Compromised workflows are designed to exfiltrate CI environment variables, AWS credentials, GCP access tokens, Azure credentials, SSH private keys, Docker and Kubernetes configurations, API keys, database connection strings, GitHub Actions tokens, and GitLab CI/CD tokens.
6.  The attacker exploits the 'workflow_dispatch' feature to create dormant backdoors.
7.  Stolen GitHub tokens are used to trigger the dormant backdoors via the GitHub API.
8.  Exfiltrated secrets are used for unauthorized access and potential lateral movement.

## Impact

Over 5,500 GitHub repositories were infected, potentially exposing sensitive credentials and secrets. The impact includes unauthorized access to cloud resources (AWS, GCP, Azure), compromised CI/CD pipelines, and potential lateral movement within victim organizations. The vulnerability in Tiledesk allowed attackers to inject malicious code into downstream projects. NPM has invalidated certain access tokens in response.

## Recommendation

*   Monitor GitHub Actions workflow creation events for unexpected or suspicious activity, specifically those authored by 'build-bot' (see Sigma rule: "Detect Suspicious GitHub Actions Workflow Creation").
*   Implement stricter code review processes for dependencies, especially open-source packages, to identify malicious commits before integration.
*   Enable and enforce two-factor authentication (2FA) on all GitHub accounts, especially those with write access to repositories.
*   Review and rotate any potentially exposed credentials, keys, and tokens identified in CI/CD environments (reference: Attack Chain step 5).
*   Scan GitHub repositories for malicious workflows or commits resembling those injected during the 'Megalodon' attack, focusing on the May 18, 2026 timeframe (reference: Attack Chain step 2).
*   Deploy the Sigma rule "Detect Malicious Commits with build-bot Author" to identify similar malicious commits in your environment.
