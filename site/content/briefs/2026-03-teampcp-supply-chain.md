---
title: TeamPCP Supply Chain Attack via CI/CD Compromise
slug: 2026-03-teampcp-supply-chain
description: TeamPCP compromised CI/CD pipelines and GitHub accounts of multiple companies by deploying an infostealer to extract credentials from CI environments, .env files, and cloud tokens, impacting projects like Trivy, KICS, and LiteLLM.
date: "2026-03-26T12:00:00Z"
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

TeamPCP is conducting a supply chain attack targeting multiple companies through the compromise of their CI/CD pipelines and GitHub accounts. The attack involves an infostealer designed to harvest sensitive information such as credentials from CI environments, contents of .env files, and cloud tokens. The compromised credentials allowed the attackers to gain unauthorized access and potentially inject malicious code into the software development lifecycle. The attack has impacted projects…
