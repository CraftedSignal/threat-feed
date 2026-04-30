---
title: TeamPCP Supply Chain Attack via CI/CD Compromise
slug: 2026-03-teampcp-supply-chain
description: TeamPCP compromised CI/CD pipelines and GitHub accounts of multiple companies by deploying an infostealer to extract credentials from CI environments, .env files, and cloud tokens, impacting projects like Trivy, KICS, and LiteLLM.
date: "2026-03-26T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - ci/cd
  - infostealer
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
references:
  - https://www.reddit.com/r/cybersecurity/comments/1s326t9/teampcp_supply_chain_attack_on_multiple_companies/
  - https://thecybersecguru.com/news/teampcp-supply-chain-attack/
rules:
  - title: Detect Infostealer Activity in CI/CD Environments
    description: Detects processes attempting to access environment variables commonly used in CI/CD pipelines.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
  - title: Detect .env File Access
    description: Detects processes reading .env files, which commonly contain sensitive credentials.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

TeamPCP is conducting a supply chain attack targeting multiple companies through the compromise of their CI/CD pipelines and GitHub accounts. The attack involves an infostealer designed to harvest sensitive information such as credentials from CI environments, contents of .env files, and cloud tokens. The compromised credentials allowed the attackers to gain unauthorized access and potentially inject malicious code into the software development lifecycle. The attack has impacted projects including Trivy, KICS, and LiteLLM, suggesting a broad targeting scope within the software development and cloud security sectors. This type of attack poses a significant risk to the integrity and security of the software supply chain, as compromised code can be distributed to numerous downstream users.

## Attack Chain

1.  Initial compromise of a developer's machine or CI/CD environment via an unspecified initial access vector.
2.  Deployment of an infostealer binary onto the compromised system.
3.  The infostealer scans the local file system for .env files containing sensitive credentials.
4.  The infostealer targets CI/CD environment variables to extract API keys, tokens, and other secrets.
5.  The infostealer searches for cloud tokens, potentially targeting AWS credentials, Azure service principals, or GCP service account keys.
6.  Extracted credentials are used to gain unauthorized access to GitHub accounts and CI/CD pipelines.
7.  Attackers inject malicious code or dependencies into the targeted projects, potentially leading to supply chain contamination.
8.  Compromised code is distributed to downstream users of Trivy, KICS, LiteLLM, and other impacted projects.

## Impact

The TeamPCP supply chain attack has impacted multiple companies and projects, including Trivy, KICS, and LiteLLM. The compromise of CI/CD pipelines and GitHub accounts allows attackers to inject malicious code into software projects, potentially affecting thousands of users. This can lead to data breaches, malware infections, and erosion of trust in the affected software. The exact number of victims is unknown, but the impact is significant due to the widespread use of the compromised projects in the cloud security and development sectors.

## Recommendation

*   Implement multi-factor authentication (MFA) on all GitHub accounts and CI/CD pipelines to prevent unauthorized access.
*   Rotate API keys and tokens regularly, especially those used in CI/CD environments, to minimize the impact of credential theft.
*   Implement secrets scanning in CI/CD pipelines to prevent accidental exposure of sensitive information in code repositories.
*   Deploy the Sigma rule "Detect Infostealer Activity in CI/CD Environments" to identify suspicious processes accessing environment variables.
*   Monitor file system access for unusual reads of .env files, using the "Detect .env File Access" Sigma rule.
*   Implement network monitoring to detect anomalous connections originating from CI/CD servers or developer workstations.
