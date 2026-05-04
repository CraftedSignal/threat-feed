---
title: Suspicious Execution from VS Code Extension
slug: 2024-01-vscode-extension-execution
description: Malicious VS Code extensions can execute arbitrary commands, leading to initial access and subsequent payload deployment on Windows systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - initial-access
  - execution
  - supply-chain-compromise
  - vscode
vendors:
  - Microsoft
products:
  - VS Code
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.aikido.dev/blog/fake-clawdbot-vscode-extension-malware
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1195/002/
rules:
  - title: Suspicious Execution from VS Code Extension
    description: Detects suspicious process execution launched from a VS Code extension context.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1195.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Newly Created Executable Execution from VS Code Extension
    description: Detects suspicious newly created executable execution launched from a VS Code extension context.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1195.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A malicious VS Code extension, configured to run upon editor startup, can execute arbitrary commands, potentially leading to the installation of remote access trojans (RATs) or other malicious payloads. The attack vector leverages the extension host under `.vscode/extensions/` to spawn processes such as script interpreters or download utilities. This activity has been observed in campaigns like the fake Clawdbot extension that installed ScreenConnect RAT. The execution can involve Living-off-the-Land binaries (LOLBins) or recently created executables from non-standard paths, posing a significant risk to Windows systems.

## Attack Chain

1. A user installs a malicious VS Code extension.
2. The extension is configured with `activationEvents: ["onStartupFinished"]` to run automatically when VS Code starts.
3. The VS Code extension host (`Code.exe` or `node.exe`) spawns a script interpreter (e.g., `powershell.exe`, `cmd.exe`) from within the `.vscode/extensions/` directory.
4. The script interpreter executes a command to download a malicious payload from a remote server using tools like `curl.exe`, `bitsadmin.exe`, or `mshta.exe`.
5. The downloaded payload is saved to disk, often in a temporary directory outside of Program Files.
6. The script interpreter executes the downloaded payload, leading to further malicious activity. For example, ScreenConnect might be installed.
7. Persistence mechanisms are established (e.g., via registry keys or scheduled tasks).
8. The attacker gains remote access to the compromised system.

## Impact

A successful attack can lead to the complete compromise of a developer's workstation, potentially affecting intellectual property and sensitive data. The installation of RATs like ScreenConnect can enable persistent remote access, allowing attackers to perform data exfiltration, lateral movement, and further malicious activities. The compromised machine can then be used as a pivot point to attack other systems within the organization.

## Recommendation

*   Deploy the "Suspicious Execution from VS Code Extension" Sigma rule to your SIEM to detect malicious process execution from VS Code extensions.
*   Monitor process creation events for script interpreters and LOLBins spawned from the `.vscode/extensions/` directory.
*   Implement application control policies to restrict the execution of unsigned or untrusted executables.
*   Regularly review and audit installed VS Code extensions for suspicious activity or unnecessary permissions.
*   Educate developers about the risks of installing extensions from untrusted sources.
*   Block the C2 domains associated with ScreenConnect and other RATs at the firewall/DNS resolver.
