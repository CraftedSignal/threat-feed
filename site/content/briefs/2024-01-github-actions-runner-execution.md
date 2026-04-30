---
title: Execution via GitHub Actions Runner
slug: 2024-01-github-actions-runner-execution
description: Adversaries compromising GitHub Actions workflows can execute arbitrary commands on runner hosts, leading to code execution, reconnaissance, credential harvesting, or network exfiltration.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - github-actions
  - supply-chain
  - execution
  - devops
vendors:
  - Elastic
mitre_ttps:
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
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/execution_via_github_actions_runner.toml
rules:
  - title: Suspicious Network Tools Executed by GitHub Actions Runner
    description: Detects the execution of network-related tools such as curl, wget, nc, or socat, spawned by the GitHub Actions Runner process, indicating potential malicious activity within the runner environment.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Shell Activity from GitHub Actions Runner Entrypoint
    description: Detects shell commands launched from the GitHub Actions Runner entrypoint script, potentially indicating malicious workflow execution.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Persistence via GitHub Actions Runner
    description: Detects the execution of persistence-related tools such as nohup and setsid, spawned by the GitHub Actions Runner process, indicating potential malicious activity within the runner environment.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1053
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This threat focuses on the exploitation of GitHub Actions runners by malicious actors. By gaining the ability to modify or trigger workflows in a linked GitHub repository, attackers can execute arbitrary commands on the runner host. The attack leverages the `Runner.Worker` process or shell interpreters launched via runner entrypoint scripts. Successful exploitation can lead to malicious workflow activity, including code execution, reconnaissance, credential harvesting, and network exfiltration. This presents a significant risk, particularly for organizations relying on self-hosted runners, as it allows attackers to potentially compromise the underlying infrastructure and sensitive data. The Elastic detection rule aims to identify such malicious activity.

## Attack Chain

1. An attacker gains unauthorized access to a GitHub repository linked to a self-hosted runner.
2. The attacker modifies an existing workflow or creates a new one to inject malicious commands.
3. The compromised workflow is triggered, initiating the `Runner.Worker` process on the runner host.
4. The `Runner.Worker` process executes a shell interpreter (e.g., bash, sh, zsh) via an entrypoint script.
5. The shell interpreter executes malicious commands specified in the compromised workflow, such as downloading a payload using `curl` or `wget`.
6. The downloaded payload is executed, establishing a reverse shell connection to an attacker-controlled server using `nc` or `socat`.
7. The attacker performs reconnaissance, credential harvesting, or lateral movement within the runner host and connected network.
8. Sensitive data is exfiltrated from the compromised runner host to the attacker's infrastructure.

## Impact

A successful attack can lead to the complete compromise of the self-hosted runner environment. This could result in the theft of sensitive source code, credentials, and other proprietary information. The attack can also be used as a stepping stone for further attacks on the organization's internal network and infrastructure. Affected sectors include software development, DevOps, and any organization using GitHub Actions with self-hosted runners.

## Recommendation

*   Deploy the Sigma rule `Execution via GitHub Actions Runner` to your SIEM to detect suspicious commands executed by the GitHub Actions Runner.
*   Monitor process creation events for commands like `curl`, `wget`, `nc`, `socat`, `powershell.exe`, `cmd.exe`, `bash`, and `ssh` spawned by `Runner.Worker` or shell interpreters with `entrypoint.sh` in their command line (see Sigma rule).
*   Implement strict access control policies for GitHub repositories and workflows to prevent unauthorized modifications.
*   Regularly review and audit GitHub Actions workflows for suspicious or unexpected commands.
*   Isolate self-hosted runners in a segmented network to limit the impact of a potential compromise.
*   Enable Sysmon process-creation logging to provide detailed process execution information for effective detection.
