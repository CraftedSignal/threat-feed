---
title: Rise in Software Supply Chain Attacks Targeting Open-Source Libraries
slug: 2026-04-supply-chain-attacks
description: Multiple supply chain attacks, including the compromise of Axios and Trivy via hijacked GitHub repositories by TeamPCP, demonstrate the increasing threat to open-source software.
date: "2026-04-03T17:31:42Z"
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - software-compromise
  - github
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://blog.talosintelligence.com/protecting-supply-chain-2026/
  - https://blog.talosintelligence.com/axois-npm-supply-chain-incident/
  - https://blog.talosintelligence.com/2025yearinreview/
rules:
  - title: Detect Installation of Potentially Compromised Packages
    description: Detects the installation of a potentially compromised package based on package name. Modify the package names to match those affected by supply chain attacks.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - process_creation
      - windows
  - title: Detect CI/CD Pipeline Modifications
    description: Detects modifications to CI/CD pipeline configuration files, indicating potential tampering.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - file_event
      - linux
  - title: Detect ClamAV Detection of TeamPCP Trojan
    description: Detects file creation events related to files flagged by ClamAV as a TeamPCP Trojan.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195.002
    data_sources:
      - file_event
      - windows
rules_count: 3
---

In early 2026, a surge in supply chain attacks has been observed, impacting widely used open-source libraries and tools. Notably, Axios, a popular HTTP client library for JavaScript with 100 million weekly downloads, was maliciously modified. Additionally, the "chaos-as-a-service" group TeamPCP injected malicious code into hijacked GitHub repositories for open-source projects, including Trivy, a security scanner. The Talos 2025 Year in Review indicated that nearly 25% of the top 100 targeted…
