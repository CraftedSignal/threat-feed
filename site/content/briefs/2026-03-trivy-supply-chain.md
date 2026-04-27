---
title: Trivy Scanner Compromised in Supply Chain Attack
slug: 2026-03-trivy-supply-chain
description: The widely used Trivy scanner has been compromised in an ongoing supply chain attack, potentially impacting numerous organizations using the tool for vulnerability management.
date: "2026-03-22T00:00:00Z"
severities:
  - high
tags:
  - supply-chain
  - vulnerability-scanner
  - trivy
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rzznag/widely_used_trivy_scanner_compromised_in_ongoing/
  - https://arstechnica.com/security/2026/03/widely-used-trivy-scanner-compromised-in-ongoing/
rules:
  - title: Detect Suspicious Outbound Connection from Trivy
    description: Detects suspicious outbound network connections initiated by the Trivy scanner, which may indicate a compromise.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Trivy Execution
    description: Detects anomalous execution of the Trivy scanner, such as running from unusual directories or with suspicious command-line arguments.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On March 21, 2026, reports emerged indicating that the Trivy scanner, a popular open-source vulnerability scanner used extensively in software development and deployment pipelines, has been compromised in a supply chain attack. The specifics of the initial compromise vector remain under investigation, but the impact could be widespread due to Trivy's integration into numerous CI/CD systems and container registries. Organizations utilizing affected versions of Trivy risk deploying vulnerable or…
