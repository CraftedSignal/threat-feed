---
title: Malicious PowerShell Execution via npm Package Lifecycle Scripts
slug: 2026-09-npm-powershell-execution
description: Malicious or compromised npm packages leverage installation lifecycle scripts to launch obfuscated PowerShell or download cradles, enabling initial access and secondary payload deployment.
date: "2026-09-28T10:10:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - npm
  - powershell
  - nodejs
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The detection focuses on PowerShell launched with an encoded command or a download cradle.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: Malicious npm packages and supply-chain compromises commonly run this from install or postinstall scripts.
    confidence_band: high
references:
  - https://www.elastic.co/blog/shai-hulud-worm-npm-supply-chain-compromise
rules:
  - title: Detect Suspicious PowerShell from npm Package Install
    description: Detects PowerShell launched with an encoded command or a download cradle whose process ancestry includes a Node.js npm package execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1195.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma-compatible rule to monitor for PowerShell processes spawned by node.js.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for detecting this specific execution pattern.
  hunt_leads:
    - lead: Search for recent process logs where parent process is node.exe and child is powershell.exe.
      technique_id: T1059.001
      data_needed:
        - Process creation events (Event ID 1)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker patterns often use this parent-child relationship to hide malicious scripts.
  mitigation_plan:
    - priority: medium_term
      action: Enforce the use of lockfiles and dependency scanning tools in CI/CD pipelines.
      owner: IT Operations
      addresses: T1195.001
      evidence: Supply chain risk reduction.
---

This threat involves the exploitation of the Node.js package ecosystem, specifically targeting npm lifecycle scripts such as 'postinstall'. Attackers distribute malicious npm packages or compromise legitimate dependencies to execute arbitrary code during the standard package installation process. The attack chain leverages the 'npx' command or standard 'npm install' routines to invoke Node.js, which subsequently spawns PowerShell processes. These PowerShell instances are used to execute encoded commands or initiate network connections via download cradles (e.g., 'Invoke-WebRequest', 'DownloadString', 'BITS'). This technique is highly effective for supply-chain compromise as it allows an attacker to execute code in developer or build environments with the privileges of the user running the installation. Defenders should monitor for suspicious process ancestry where Node.js spawns PowerShell, particularly when the command line includes obfuscation or common download cradle functions.

## Attack Chain

1. Attacker publishes a malicious package to the public npm registry or compromises a legitimate, widely-used dependency.
2. A developer or automated build system executes 'npm install' or 'npx &lt;package>' within an environment.
3. The npm client initializes the Node.js runtime, invoking 'npm-cli.js' or 'npx-cli.js'.
4. The package's 'postinstall' script triggers, executing a system command via Node.js.
5. The spawned process initiates a PowerShell instance to bypass execution policy or obfuscate activity.
6. The PowerShell script uses download cradles (e.g., 'IEX', 'Net.WebClient') to fetch a secondary stage payload from an attacker-controlled remote server.
7. The secondary payload is executed in memory or written to disk to establish persistence or remote command-and-control access.

## Impact

Successful exploitation results in unauthorized code execution within the victim's development or build environment. This can lead to credential theft, intellectual property exfiltration, the injection of malicious code into downstream software products, and further lateral movement within the organization's CI/CD pipeline.

## Recommendation

Prioritize visibility into developer and build environment process lineage. Enable process-creation logging and specifically monitor for instances where 'node.exe' serves as the parent process to 'powershell.exe'. 

- Deploy detection rules that inspect process ancestry to identify PowerShell spawned from Node.js (specifically 'npm-cli.js' or 'npx-cli.js').
- Audit 'package.json' files in local repositories for suspicious lifecycle scripts (e.g., 'preinstall', 'postinstall').
- Review network logs for outbound connections from build servers to unknown or high-risk domains, especially when initiated by PowerShell.
- Implement and enforce dependency locking (e.g., 'package-lock.json') to mitigate risks from malicious package updates.
