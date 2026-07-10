---
title: Execution via GitHub Actions Runner
slug: 2024-01-github-actions-execution
description: Compromised GitHub Actions workflows allow attackers to execute arbitrary commands on self-hosted runners, leading to code execution, file manipulation, and potential data exfiltration.
date: "2024-01-09T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - github-actions
  - supply-chain
  - execution
vendors:
  - GitHub
products:
  - GitHub Actions Runner
mitre_ttps:
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
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.elastic.co/blog/shai-hulud-worm-npm-supply-chain-compromise
  - https://socket.dev/blog/shai-hulud-strikes-again-v2
rules:
  - title: Execution via GitHub Actions Runner - Suspicious Tools
    description: Detects suspicious tools spawned by the GitHub Actions Runner process, indicating potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
      - T1195
    data_sources:
      - process_creation
      - windows|linux|macos
  - title: Execution via GitHub Actions Runner - Suspicious Location
    description: Detects suspicious execution from /tmp or similar directories by a Github Actions runner.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1195
    data_sources:
      - process_creation
      - linux|macos
rules_count: 2
---

Attackers can exploit self-hosted GitHub Actions runners by gaining the ability to modify or trigger workflows in a linked GitHub repository. This allows the execution of arbitrary commands on the runner host, potentially leading to malicious or unexpected workflow activity. This includes unauthorized code execution, file manipulation, and network exfiltration, all initiated through a compromised repository. The attacks observed leverage a variety of scripting languages and tools, including curl, wget, PowerShell, and others, to achieve their objectives, which necessitates comprehensive monitoring across different platforms. The incident observed aligns with supply chain compromise attack vectors.

## Attack Chain

1. An attacker gains control of a GitHub repository linked to a self-hosted Actions runner, potentially through compromised credentials or a vulnerable dependency.
2. The attacker modifies a workflow file (.yml) in the repository to include malicious commands, such as downloading and executing a reverse shell.
3. The compromised workflow is triggered, either manually or by a scheduled event, causing the GitHub Actions Runner to execute the attacker's malicious code.
4. The `Runner.Worker` process spawns a command interpreter (e.g., `powershell.exe`, `bash`) to execute the attacker-controlled commands embedded in the workflow.
5. The attacker utilizes tools like `curl` or `wget` to download additional payloads or scripts from external sources to the runner machine.
6. Using `certutil.exe` the attacker downloads and decodes additional payloads.
7. The attacker establishes persistence by adding a scheduled task or modifying registry keys using commands executed via the GitHub Actions runner.
8. The attacker exfiltrates sensitive data from the runner host to an external server using tools like `curl` or `powershell`.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the self-hosted runner machine. This can lead to the compromise of sensitive data stored on the runner, such as credentials or API keys. Attackers can also use the compromised runner as a pivot point to gain access to other internal systems. Observed attacks have focused on supply chain compromises with an unknown number of victims. The impact can range from data breaches and financial loss to reputational damage.

## Recommendation

*   Deploy the Sigma rule "Execution via GitHub Actions Runner - Suspicious Tools" to detect the execution of common attacker tools spawned by the GitHub Actions runner (rule: Execution via GitHub Actions Runner - Suspicious Tools).
*   Monitor process execution logs for child processes of `Runner.Worker` or `Runner.Worker.exe` that execute suspicious commands (log source: process_creation).
*   Implement application whitelisting to prevent unauthorized execution of binaries on the self-hosted runner machines (general hardening guidance).
*   Review and audit GitHub workflow configurations for any unauthorized or suspicious modifications (GitHub audit logs).
