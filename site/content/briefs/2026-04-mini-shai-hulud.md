---
title: Mini Shai-Hulud Supply Chain Attack Targets SAP-Related npm Packages
slug: 2026-04-mini-shai-hulud
description: The 'mini Shai-Hulud' campaign compromised SAP-related npm packages with credential-stealing malware, exfiltrating sensitive data to public GitHub repositories and propagating through developer workflows.
date: "2026-04-29T16:26:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
actors:
  - TeamPCP (Likely)
tags:
  - supply-chain
  - npm
  - credential-theft
  - malware
  - github
vendors:
  - SAP
products:
  - SAP JavaScript
  - SAP Cloud Application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html
rules:
  - title: Detect Mini Shai-Hulud Preinstall Script
    description: Detects the execution of a malicious preinstall script in npm packages, which downloads and executes the Bun JavaScript runtime.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1027
      - T1189
    data_sources:
      - process_creation
      - windows
  - title: Detect Mini Shai-Hulud Github Repo Creation
    description: Detects the creation of public GitHub repositories with the specific description 'A Mini Shai-Hulud has Appeared', indicating potential exfiltration.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1567
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The "mini Shai-Hulud" campaign is a supply chain attack targeting SAP's JavaScript and cloud application development ecosystem. Active as of April 29, 2026, the campaign compromised multiple npm packages, including `mbt@1.2.48`, `@cap-js/db-service@2.10.1`, `@cap-js/postgres@2.2.2`, and `@cap-js/sqlite@2.2.2`. The compromised packages introduced a preinstall script that downloads and executes a platform-specific Bun binary from GitHub Releases. Wiz assesses this campaign likely links to the TeamPCP threat actor, due to similarities with previous operations. The malware harvests credentials and secrets from developers' local environments, GitHub Actions, and cloud platforms (AWS, Azure, GCP, Kubernetes), exfiltrating them to public GitHub repositories. The attack also self-propagates by injecting malicious GitHub Actions workflows into victim repositories to steal repository secrets and publish poisoned npm packages.

## Attack Chain

1.  **Account Compromise:** Attackers compromised npm accounts, such as RoshniNaveenaS for the "@cap-js" packages and potentially "cloudmtabot" for the mbt package.
2.  **Malicious Package Injection:** Modified workflows were pushed to non-main branches. For "@cap-js" packages, attackers exploited a misconfiguration in npm's OIDC trusted publisher setup.
3.  **Preinstall Hook Execution:** The compromised npm packages included a malicious "preinstall" script within their `package.json` files.
4.  **Bun Runtime Download and Execution:** The "preinstall" script downloads a platform-specific Bun JavaScript runtime from GitHub Releases. The implementation follows HTTP redirects without validation.
5.  **Credential Stealing:** The downloaded Bun runtime executes a credential stealer ("execution.js") designed to harvest local developer credentials, GitHub and npm tokens, GitHub Actions secrets, and cloud secrets from AWS, Azure, GCP, and Kubernetes.
6.  **Data Exfiltration:** Stolen credentials and secrets are encrypted using AES-256-GCM (with the key encapsulated using RSA-4096) and exfiltrated to public GitHub repositories created on the victim's own account, with the description "A Mini Shai-Hulud has Appeared."
7.  **Self-Propagation:** The malware injects a malicious GitHub Actions workflow into the victim's repositories using stolen GitHub and npm tokens, allowing it to steal repository secrets and publish poisoned versions of the npm packages.
8.  **Persistence:** The payload commits itself into every accessible GitHub repository by injecting a ".claude/settings.json" file (abusing Claude Code's SessionStart hook) and a ".vscode/tasks.json" file (with "runOn": "folderOpen") so that any attempt to open the infected repository in Microsoft Visual Studio Code (VS Code) or Claude Code causes the malware to be executed.

## Impact

The "mini Shai-Hulud" campaign compromises developer environments and CI/CD pipelines, leading to widespread credential theft and supply chain poisoning. Over 1,100 GitHub repositories have been identified with the "A Mini Shai-Hulud has Appeared" description, indicating a significant number of victims. Successful exploitation allows attackers to steal sensitive cloud and development credentials, potentially leading to data breaches, code tampering, and further supply chain attacks. The attack's self-propagation capabilities exacerbate the spread and impact.

## Recommendation

*   Deploy the "Detect Mini Shai-Hulud Preinstall Script" Sigma rule to detect the execution of the malicious preinstall script during npm package installation.
*   Deploy the "Detect Mini Shai-Hulud Github Repo Creation" Sigma rule to detect the creation of GitHub repositories with the description "A Mini Shai-Hulud has Appeared."
*   Monitor npm package installations for the presence of suspicious `preinstall` scripts that download and execute external binaries.
*   Review and harden npm OIDC trusted publisher configurations to ensure they only trust canonical release workflows on the main branch.
*   Implement multi-factor authentication (MFA) on all developer accounts and CI/CD systems to prevent account compromise.
*   Audit GitHub Actions workflows for suspicious activity, such as the injection of malicious steps.
