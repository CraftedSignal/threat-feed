---
title: Trivy Ecosystem Supply Chain Compromise
slug: 2026-03-trivy-supply-chain
description: A threat actor compromised the Trivy ecosystem supply chain by publishing malicious releases of Trivy binaries, container images, and GitHub Actions to steal credentials, with observed impacts including exfiltration to attacker-controlled infrastructure and public repositories.
date: "2026-03-25T12:00:00Z"
type: coverage
types:
  - coverage
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
iocs:
  - type: domain
    value: get.trivy.dev
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

On March 19 and 22, 2026, a threat actor compromised the Trivy ecosystem by leveraging compromised credentials. This resulted in the publication of malicious releases, including Trivy v0.69.4 binaries and container images, v0.69.5 and v0.69.6 DockerHub images, and malicious versions of the `aquasecurity/trivy-action` and `aquasecurity/setup-trivy` GitHub Actions. The attacker injected an infostealer into the GitHub Actions to collect secrets. The malicious code targeted SSH keys, AWS/GCP/Azure credentials, Kubernetes tokens, Docker configs, `.env` files, database credentials, and cryptocurrency wallets. This attack affected users who utilized the compromised versions within specific exposure windows and highlights the risks associated with supply chain vulnerabilities in widely used security tools. The incident underscores the importance of immutable releases, dependency verification, and robust credential management practices.

## Attack Chain

1. The attacker gained unauthorized access to credentials used to manage the Trivy project's GitHub repository and Docker Hub account.
2. The attacker pushed a malicious commit (`1885610c`) to the Trivy repository, which swapped the `actions/checkout` reference to a malicious commit (`70379aad`). This malicious commit contained a composite action to download Go source files from a typosquatted domain (get.trivy.dev).
3. The attacker tagged the malicious commit as `v0.69.4`, triggering the automated release pipeline.
4. The malicious release was distributed across various Trivy distribution channels, including GitHub Releases, GHCR, ECR Public, Docker Hub, deb/rpm packages, and `get.trivy.dev`.
5. For the `trivy-action` GitHub Action, the attacker force-pushed 76 of 77 version tags to malicious commits, injecting an infostealer into `entrypoint.sh`.
6. The infostealer collected secrets by dumping process memory and sweeping the filesystem for sensitive files and credentials.
7. The stolen data was encrypted using AES-256-CBC with RSA-4096 hybrid encryption.
8. The encrypted data was transmitted to attacker-controlled infrastructure. As a fallback, if exfiltration failed and `INPUT_GITHUB_PAT` was set, the attacker created a public repository named `tpcp-docs` on the victim's GitHub account and uploaded the stolen data as a release asset.

## Impact

The Trivy supply chain compromise had a critical impact, potentially exposing sensitive credentials and secrets of numerous users and organizations that rely on Trivy for security scanning and vulnerability management. While the exact number of victims remains unknown, the widespread use of Trivy binaries, container images, and GitHub Actions suggests a broad potential impact. Successful exploitation could lead to unauthorized access to cloud environments, data breaches, and other security incidents. The creation of public `tpcp-docs` repositories on victim's GitHub accounts serves as a clear indicator of successful exfiltration and data compromise.

## Recommendation

*   Upgrade to a known-safe version of Trivy (v0.69.2 or v0.69.3) and the `trivy-action` (v0.35.0) and `setup-trivy` (v0.2.6) GitHub Actions as listed in the advisory.
*   Rotate all potentially exposed secrets accessible to affected pipelines if there is any possibility that a compromised version of Trivy ran in a project's environment as stated in the overview.
*   Audit GitHub Action references in all workflows using `aquasecurity/trivy-action` or `aquasecurity/setup-trivy`, checking workflow run logs from March 19–20, 2026 for signs of compromise, and search for repositories named `tpcp-docs` in your GitHub organization, as described in the "Recommended Actions" section.
*   Block the domain `get.trivy.dev` at the network perimeter to prevent access to potentially malicious resources served from the typosquatted domain, based on the "Attack Details" section.
