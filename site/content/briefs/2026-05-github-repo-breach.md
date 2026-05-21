---
title: GitHub Breach Linked to TanStack npm Supply Chain Attack via Malicious VS Code Extension
slug: 2026-05-github-repo-breach
description: GitHub experienced a breach affecting 3,800 internal repositories due to a supply chain attack targeting TanStack npm packages; the attacker compromised an employee's machine via a malicious version of the Nx Console VS Code extension and gained access to internal GitHub repositories by stealing credentials and secrets.
date: "2026-05-21T06:54:47Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - vscode
  - npm
  - github
  - credential-theft
vendors:
  - GitHub
  - Microsoft
  - TanStack
  - Mistral AI
  - UiPath
  - Guardrails AI
  - OpenSearch
products:
  - Nx Console
  - github.com
  - Visual Studio Code Marketplace
  - OpenVSX
  - GitHub CLI
  - TanStack npm packages
  - Mistral AI npm packages
  - UiPath
  - Guardrails AI
  - OpenSearch
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://www.bleepingcomputer.com/news/security/github-links-repo-breach-to-tanstack-npm-supply-chain-attack/
rules:
  - title: Detect Suspicious VS Code Extension Execution
    description: Detects execution of potentially malicious VS Code extensions based on the process name.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
  - title: Detect Credential Theft via Malicious VS Code Extension
    description: Detects credential theft attempts by VS Code extensions based on malicious filenames or file paths.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

On May 21, 2026, GitHub revealed that a breach affecting 3,800 internal repositories occurred due to a supply chain attack. This attack, attributed to the TeamPCP threat group, originated with the compromise of TanStack npm packages and quickly spread to other projects including UiPath, Guardrails AI, and OpenSearch. The initial compromise involved a malicious version of the Nx Console Visual Studio Code (VS Code) extension. The attacker gained access by compromising a developer's machine, stealing credentials, and exploiting the GitHub CLI (gh) to run workflows on the GitHub repository as a contributor. While GitHub has secured the compromised device and rotated critical secrets, the incident highlights the significant risks associated with supply chain attacks targeting developer tools and code repositories.

## Attack Chain

1. The attacker compromises the TanStack npm packages in a supply chain attack.
2. A developer installs the malicious Nx Console (version 18.95.0) VS Code extension from the Visual Studio Marketplace or OpenVSX.
3. The malicious extension executes a payload designed to steal credentials and secrets for platforms like npm, AWS, Kubernetes, GitHub, and GCP/Docker.
4. The compromised developer's GitHub credentials are leaked through the GitHub CLI (gh).
5. The attacker uses the stolen GitHub credentials to authenticate and run workflows on the GitHub repository.
6. The attacker gains unauthorized access to approximately 3,800 of GitHub's internal repositories.
7. The attacker exfiltrates source code and other sensitive data from the breached repositories.
8. TeamPCP attempts to sell the stolen data for at least $50,000 on the Breached forum.

## Impact

The successful exploitation resulted in the unauthorized access to approximately 3,800 of GitHub's internal repositories. The attacker, TeamPCP, is attempting to sell the stolen data, including source code, for at least $50,000. This breach could lead to the exposure of sensitive internal code, security vulnerabilities, and proprietary information, potentially impacting GitHub's competitive advantage and the security of its platform. The incident underscores the increasing risk of supply chain attacks targeting developer tools and the need for robust security measures to protect against compromised dependencies.

## Recommendation

*   Monitor VS Code extension installations and deployments for suspicious activity, focusing on extensions related to Nx Console or TanStack, using a process creation rule (see "Detect Suspicious VS Code Extension Execution").
*   Implement multi-factor authentication (MFA) for all developer accounts and regularly rotate credentials for critical services such as npm, AWS, Kubernetes, GitHub, and GCP/Docker.
*   Deploy the Sigma rule "Detect Credential Theft via Malicious VS Code Extension" to identify attempts to steal credentials using known malicious file names or file paths.
*   Monitor network connections originating from VS Code extensions to detect unauthorized data exfiltration or communication with suspicious domains or IP addresses.
*   Review and harden CI/CD pipelines to prevent the use of stolen credentials, focusing on securing access to sensitive resources and monitoring for unauthorized workflow executions.
