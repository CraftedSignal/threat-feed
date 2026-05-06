---
title: Increased npm Supply Chain Attacks Targeting SAP Developers
slug: 2026-05-npm-supply-chain
description: Threat actors are compromising npm packages, including those targeting SAP developers, to steal credentials, embed themselves in CI/CD pipelines, and deploy multi-stage payloads using techniques like wormable propagation and covert C2 channels on GitHub.
date: "2026-05-02T00:10:33Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - npm
  - supply-chain
  - credential-theft
  - github
vendors:
  - npm
  - GitHub
  - SAP
  - Bitwarden
  - Checkmarx
  - Microsoft
products:
  - '@bitwarden/cli (2026.4.0)'
  - '@cap-js/sqlite (2.2.2)'
  - '@cap-js/postgres (2.2.2)'
  - '@cap-js/db-service (2.10.1)'
  - mbt (1.2.48)
  - SAP Cloud Application Programming (CAP) Model
  - checkmarx/kics
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: JavaScript'
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.003
    technique_name: 'Event Triggered Execution: Windows Management Instrumentation Event Subscription'
references:
  - https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/
iocs:
  - type: domain
    value: audit.checkmarx[.]cx
ioc_counts:
  domain: 1
rules:
  - title: Detect Suspicious Bun Process Execution
    description: Detects the execution of the Bun JavaScript runtime from temporary directories, which is indicative of the Mini Shai-Hulud campaign.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Github Commit By Claude Email
    description: Detects commits authored with the email claude@users.noreply.github.com, indicating a malicious commit.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The npm ecosystem is experiencing a surge in sophisticated supply chain attacks following the Shai-Hulud worm in September 2025. Attackers, including TeamPCP, are actively compromising npm packages to gain access to sensitive information and establish persistence within CI/CD pipelines. The attacks have evolved to include wormable propagation, infrastructure-level persistence, and multi-stage payloads designed to evade detection. In April 2026, two campaigns were observed: one included the string "Shai-Hulud: The Third Coming," and the other, dubbed "Mini Shai-Hulud," targeted the SAP developer ecosystem. The compromised packages are often part of SAP's Cloud Application Programming (CAP) Model and multitarget application (MTA) build toolchain, increasing the likelihood of impacting enterprise developers and CI/CD pipelines with access to cloud credentials and GitHub tokens.

## Attack Chain

1. Initial Compromise: Attackers compromise legitimate npm packages, such as @cap-js/sqlite, @cap-js/postgres, @cap-js/db-service, and mbt, by injecting malicious code.
2. Malicious Code Injection: Compromised packages receive two new files: setup.mjs and execution.js, along with a modified package.json containing a "preinstall" hook.
3. Execution of setup.mjs: During the `npm install` process, the preinstall hook executes setup.mjs, which detects the host OS and architecture.
4. Bun Runtime Download and Execution: setup.mjs downloads the Bun JavaScript runtime (v1.3.13) from GitHub releases and extracts it to a temporary directory.
5. Execution of execution.js: The Bun runtime executes execution.js, a large (11.7 MB) obfuscated credential stealer and propagation framework.
6. Credential Harvesting: execution.js harvests GitHub tokens, npm tokens, environment variables, GitHub Actions secrets, AWS STS identity, Azure Key Vault secrets, GCP Secret Manager values, and Kubernetes service account tokens. It also targets Claude and MCP configuration files and Electrum wallets.
7. Data Exfiltration: The collected data is compressed, encrypted, and exfiltrated to freshly created public GitHub repositories with randomized names and descriptions.
8. Propagation: The malware searches for commits containing the keyword "OhNoWhatsGoingOnWithGitHub," decodes matching commit messages as a token dead-drop, recovers stolen GitHub tokens, and uses them to spread the malware to other packages.

## Impact

Compromised npm packages can lead to the theft of sensitive credentials, including cloud provider credentials, GitHub tokens, and CI/CD secrets. Successful attacks can result in unauthorized access to cloud infrastructure, code repositories, and deployment pipelines. The Mini Shai-Hulud campaign targeted packages with approximately 570,000 weekly downloads, potentially impacting a large number of SAP developers and enterprise environments. The attackers use stolen credentials to further propagate the malware, increasing the scale and scope of the compromise.

## Recommendation

*   Rotate npm tokens and GitHub Personal Access Tokens (PATs) immediately if any affected packages were installed (refer to the list of affected packages in the IOC table).
*   Monitor npm install processes for unexpected execution of `node setup.mjs` (see Attack Chain).
*   Implement the Sigma rule "Detect Suspicious Bun Process Execution" to identify potential execution of the Bun runtime from temporary directories.
*   Monitor network connections for unusual processes connecting to `api.github[.]com/search/commits?q=OhNoWhatsGoingOnWithGitHub` (see IOCs) to detect potential C2 activity.
*   Deploy the Sigma rule "Detect Github Commit By Claude Email" to identify commits authored with the email `claude@users.noreply.github.com` to detect malicious commits.
