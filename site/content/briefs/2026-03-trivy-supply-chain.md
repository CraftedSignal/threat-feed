---
title: Trivy Ecosystem Supply Chain Compromise
slug: 2026-03-trivy-supply-chain
description: A threat actor compromised the Trivy ecosystem supply chain by publishing malicious releases of Trivy binaries, container images, and GitHub Actions to steal credentials, with observed impacts including exfiltration to attacker-controlled infrastructure and public repositories.
date: "2026-03-25T12:00:00Z"
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
references:
  - https://github.com/advisories/GHSA-69fq-xp46-6x23
ioc_counts:
  domain: 1
rules:
  - title: Detect Public Repository Creation After Trivy Compromise
    description: Detects the creation of a public repository named `tpcp-docs` on GitHub, potentially indicating successful secret exfiltration following the Trivy supply chain compromise.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1133
    data_sources:
      - webserver
      - github
  - title: Detect Outbound Connection to Typosquatted Trivy Domain
    description: Detects network connections to the typosquatted domain get.trivy.dev, which was used to serve malicious Go source files during the Trivy supply chain compromise.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 19 and 22, 2026, a threat actor compromised the Trivy ecosystem by leveraging compromised credentials. This resulted in the publication of malicious releases, including Trivy v0.69.4 binaries and container images, v0.69.5 and v0.69.6 DockerHub images, and malicious versions of the `aquasecurity/trivy-action` and `aquasecurity/setup-trivy` GitHub Actions. The attacker injected an infostealer into the GitHub Actions to collect secrets. The malicious code targeted SSH keys, AWS/GCP/Azure…
