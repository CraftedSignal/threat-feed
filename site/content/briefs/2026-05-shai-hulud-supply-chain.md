---
title: Shai-Hulud Malware Used in Supply Chain Attack via Compromised npm Packages
slug: 2026-05-shai-hulud-supply-chain
description: The Shai-Hulud malware was used in a large-scale software supply-chain attack compromising hundreds of packages across open-source software ecosystems by compromising developer secrets and CI/CD pipelines.
date: "2026-05-12T11:30:55Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - TeamPCP
tags:
  - supply-chain
  - supply-chain-attack
  - npm
  - pypi
  - credential-theft
  - shai-hulud
vendors:
  - TanStack
  - Mistral AI
  - Guardrails AI
  - UiPath
  - OpenSearch
  - Bitwarden
  - SAP
  - GitHub
  - npm
  - SafeDep
  - Snyk
products:
  - router
  - Node Package Manager (npm)
  - Bitwarden CLI
  - Commerce Cloud
  - S/4HANA
  - AWS Secrets Manager
  - IAM
  - ESC task
  - Kubernetes
  - HashiCorp Vault
  - Claude Code
  - VS Code
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1600
    technique_name: Archive Collected Data
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1538
    technique_name: Replication Through Removable Media
references:
  - https://www.bleepingcomputer.com/news/security/shai-hulud-attack-ships-signed-malicious-tanstack-mistral-npm-packages/
  - '[1]'
  - '[2]'
  - '[3]'
  - '[4]'
  - '[5]'
iocs:
  - type: domain
    value: api.masscan.cloud
  - type: domain
    value: git-tanstack.com
  - type: domain
    value: '*.getsession.org'
ioc_counts:
  domain: 3
rules:
  - title: Detect Malicious npm Package Installation
    description: Detects the installation of potentially malicious npm packages based on the presence of suspicious file names after package installation
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - file_event
      - windows
  - title: Detect Outbound Connections to Shai Hulud C2 Domains
    description: Detects outbound network connections to known Shai Hulud command and control domains.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Stealing GitHub Actions Secrets via Process Memory Access
    description: Detects processes accessing process memory of GitHub Actions runners, which may indicate credential theft.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

A large-scale software supply-chain attack involving the "Shai-Hulud" malware has compromised hundreds of packages across open-source software ecosystems, including npm, PyPI, and Composer. The attack, attributed to the TeamPCP threat group, began by compromising dozens of TanStack and Mistral AI packages and quickly extended to other popular projects, including Guardrails AI, UiPath, OpenSearch, Bitwarden CLI, and SAP packages. The attacker hijacked valid OpenID Connect (OIDC) tokens to publish malicious package versions with verifiable provenance attestation (SLSA Build Level 3) via legitimate CI/CD pipelines. The latest attack wave occurred recently, with the threat actor publishing multiple malicious packages in the TanStack namespaces on the Node Package Manager (npm), and then spreading to other projects using stolen CI/CD credentials.

## Attack Chain

1.  The attacker compromises legitimate CI/CD pipelines, potentially by exploiting vulnerabilities such as a risky '&lsquo;pull_request-target&rsquo;' workflow, GitHub Actions cache poisoning, and OIDC token theft from runner memory.
2.  The attacker gains access to valid OpenID Connect (OIDC) tokens and GitHub/npm credentials.
3.  Using the compromised credentials, the attacker publishes malicious package versions with verifiable provenance attestation (SLSA Build Level 3) on package repositories such as npm, PyPI, and Composer.
4.  The attacker modifies package tarballs to inject malicious payloads into popular projects.
5.  Developers unknowingly download and install the compromised packages, which contain credential-stealing malware.
6.  The malware reads GitHub Actions process memory to collect credentials from various file paths associated with cloud providers, cryptocurrency tokens, and messaging apps.
7.  The malware exfiltrates stolen developer secrets, including GitHub tokens, npm tokens, AWS credentials, Vault tokens, and Kubernetes service accounts, via the Session P2P network.
8.  The malware writes itself into Claude Code hooks and VS Code auto-run tasks for persistence, ensuring it survives uninstallation of the malicious packages.

## Impact

Hundreds of packages across npm, PyPI, and Composer have been compromised. Over 160 compromised packages were found on npm by Endor Labs, Aikido recorded 373 malicious package-version entries, and Socket tracked 416 compromised package artifacts. Developers who downloaded affected package versions should assume their credentials were exposed. Successful attacks can lead to the theft of sensitive credentials, enabling further unauthorized access and potentially impacting cloud infrastructure, source code repositories, and sensitive data stores.

## Recommendation

*   Check for affected package versions in your projects, as identified in reports from security vendors [references].
*   Rotate all potentially exposed credentials (GitHub tokens, npm tokens, AWS credentials, Vault tokens, Kubernetes service accounts, and CI/CD secrets) as recommended by researchers.
*   Audit IDE directories for malicious files surviving npm install (e.g., router_runtime.js or setup.mjs).
*   Block the threat actor's command-and-control infrastructure (api.masscan.cloud, git-tanstack.com, and *.getsession.org) at the DNS or proxy level.
*   Implement behavioral analysis at install time, along with signature-based checks for malicious packages, as suggested by Snyk researchers.
*   Consider enforcing lockfile-only installs to prevent auto/silent package updates to mitigate the risk from similar attacks.
