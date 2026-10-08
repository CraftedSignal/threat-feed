---
title: Malicious TensorLake npm SDK Hijacks Developer Environments
slug: 2026-10-tensorlake-compromise
description: A malicious npm release of the TensorLake TypeScript SDK (v0.5.144) uses a preinstall hook to exfiltrate developer credentials and AI-tool configurations while maintaining remote command execution capabilities.
date: "2026-10-08T19:57:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - npm
  - credential-theft
  - javascript
vendors:
  - GitHub
  - HashiCorp
products:
  - tensorlake (0.5.144)
  - GitHub
  - HashiCorp Vault
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: A malicious release of TensorLake's TypeScript SDK, tensorlake@0.5.144, used an install hook to search for developer credentials.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The affected npm release included a preinstall hook that starts an obfuscated JavaScript payload through Bun.
    confidence_band: high
rules:
  - title: Detect Malicious TensorLake Preinstall Hook
    description: Detects the execution of the malicious tensorlake@0.5.144 package via its preinstall script hook
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit GitHub audit logs for repository modifications
      owner: SOC
      due: 24h
      evidence: Review GitHub audit activity for unexpected access, repository creation, and commits across branches.
  hunt_leads:
    - lead: Search for 'globalThis.WORMTAG' with value 'tensrlake'
      technique_id: T1059
      data_needed:
        - Process memory dumps
        - Runtime logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The payload sets globalThis.WORMTAG to tensrlake.
  mitigation_plan:
    - priority: immediate
      action: Rotate all credentials accessible to developer environments
      owner: IT Operations
      addresses: GitHub and HashiCorp Vault tokens
      evidence: Anyone who installed tensorlake@0.5.144 should treat credentials available to that environment as potentially exposed.
  gaps:
    - Telemetry for credential access from within Node processes
---

A malicious version of the TensorLake TypeScript SDK, identified as tensorlake@0.5.144, was distributed via the npm registry. The package contains a obfuscated JavaScript payload triggered by a preinstall hook, which attempts to download the Bun runtime if not already present on the host system. The primary goal of the payload is the theft of sensitive developer credentials, including GitHub tokens and HashiCorp Vault secrets, alongside configuration files for various AI-assisted development tools like Claude, Cursor, and Kiro MCP. The malware includes a command-and-control mechanism that allows for arbitrary JavaScript evaluation. Notably, the payload includes logic to exfiltrate collected data by creating public GitHub repositories and committing stolen tokens to them. While the payload includes checks to avoid execution in common CI/CD environments, it actively targets developer workstations for potential lateral movement and persistence through the modification of .vscode and .claude configuration files within local repositories.

## Attack Chain

1. Victim installs the malicious package tensorlake@0.5.144, triggering the 'preinstall' hook defined in package.json.
2. The hook executes an obfuscated 'setup.mjs' script, which checks for CI/CD environment variables to determine if it should proceed.
3. The script downloads or invokes the Bun runtime to execute the malicious JavaScript payload.
4. The payload performs local reconnaissance to identify stored GitHub tokens, HashiCorp Vault credentials, and configuration files for AI coding assistants.
5. The malware establishes a command-and-control channel to poll for and execute remote JavaScript commands.
6. The code attempts to exfiltrate harvested secrets by creating a public GitHub repository and committing data to a 'results/' directory.
7. The payload modifies project-level configuration files (.vscode, .claude) in accessible repositories to establish persistence or facilitate downstream execution.

## Impact

Successful exploitation leads to the exposure of high-privilege credentials, including GitHub tokens and HashiCorp Vault secrets, potentially enabling unauthorized access to private corporate infrastructure. The injection of configuration files into local repositories poses a significant risk of downstream contamination, allowing the malicious code to spread to other developers who interact with the compromised codebases. No broad CI/CD infection has been confirmed, but the potential for developer environment compromise is severe.

## Recommendation

1. Identify all instances of 'tensorlake@0.5.144' in local environments, CI/CD runners, and package lockfiles.
2. Search for the presence of 'globalThis.WORMTAG' with the value 'tensrlake' in active memory or running processes to identify affected systems.
3. Treat all credentials accessible to developers who installed the package as compromised; rotate GitHub tokens and HashiCorp Vault secrets immediately.
4. Audit GitHub repository activity for unauthorized repository creation or anomalous commits to '.vscode', '.claude', and 'results/' directories.
5. Inspect developer workstations for unexpected 'preinstall' hook executions during npm package installation.
6. Implement egress filtering to block communication to suspicious command-and-control infrastructure identified via forensic analysis of the 'setup.mjs' payload.
