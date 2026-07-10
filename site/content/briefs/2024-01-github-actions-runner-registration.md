---
title: Detection of Unauthorized GitHub Actions Runner Registration
slug: 2024-01-github-actions-runner-registration
description: The configuration of a GitHub Actions self-hosted runner using the Runner.Listener binary can indicate malicious activity aimed at establishing remote code execution via malicious GitHub workflows.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - github-actions
  - supply-chain
  - remote-code-execution
vendors:
  - GitHub
products:
  - GitHub Actions Runner
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Tools
references:
  - https://www.elastic.co/blog/shai-hulud-worm-npm-supply-chain-compromise
  - https://socket.dev/blog/shai-hulud-strikes-again-v2
rules:
  - title: Remote GitHub Actions Runner Registration
    description: Detects the configuration of a GitHub Actions self-hosted runner using the Runner.Listener binary.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
      - initial_access
    techniques:
      - T1059
      - T1195
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Suspicious GitHub Actions Runner Process Arguments
    description: Detects suspicious process arguments used during GitHub Actions runner registration.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
      - initial_access
    techniques:
      - T1059
      - T1195
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Linux GitHub Actions Runner Registration
    description: Detects the configuration of a GitHub Actions self-hosted runner using the Runner.Listener binary on Linux.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
      - initial_access
    techniques:
      - T1059
      - T1195
      - T1219
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This threat brief focuses on the malicious registration of GitHub Actions self-hosted runners. The attack involves adversaries registering a machine as a runner to a remote GitHub repository. Once registered, the attacker gains the ability to execute arbitrary workflow commands on the host. This can lead to supply chain compromise, remote code execution, and potentially lateral movement within a network. The rule detects the execution of `Runner.Listener` or `Runner.Listener.exe` with the `configure`, `--url`, and `--token` arguments, which are indicative of runner registration. This activity is particularly concerning as it provides a persistent remote access mechanism that bypasses traditional security controls.

## Attack Chain

1.  Attacker gains initial access to a system via various methods (e.g., compromised credentials, phishing, exploiting vulnerabilities).
2.  Attacker downloads the GitHub Actions Runner software to the compromised host.
3.  Attacker executes `Runner.Listener` or `Runner.Listener.exe` with the `configure` argument.
4.  The attacker provides the `--url` argument, pointing to a malicious or attacker-controlled GitHub repository.
5.  The attacker provides the `--token` argument, authenticating the runner against the malicious repository.
6.  The compromised system registers as a self-hosted runner within the attacker's GitHub repository.
7.  The attacker creates or modifies workflows in the GitHub repository to execute arbitrary commands on the registered runner.
8.  The attacker triggers the malicious workflow, leading to command execution on the compromised host, potentially enabling data exfiltration, lateral movement, or the deployment of malware.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the registered runner machine. This can lead to data exfiltration, installation of malware, or use of the compromised system as a pivot point for further lateral movement within the network. The compromise can also lead to supply chain attacks if the runner has access to sensitive build processes or deployment pipelines. The scope of impact depends on the privileges of the account running the GitHub Actions Runner and the resources accessible from that host.

## Recommendation

*   Deploy the Sigma rule "Remote GitHub Actions Runner Registration" to detect the execution of `Runner.Listener` with suspicious arguments (logsource: process_creation).
*   Investigate any alerts triggered by the Sigma rule "Remote GitHub Actions Runner Registration", focusing on the associated network and file activities.
*   Implement application whitelisting to prevent unauthorized execution of binaries like `Runner.Listener` and `Runner.Listener.exe` (logsource: process_creation).
*   Review GitHub repository details for any suspicious workflows or run commands, particularly in the `.github/workflows` folder (reference: [https://www.elastic.co/blog/shai-hulud-worm-npm-supply-chain-compromise](https://www.elastic.co/blog/shai-hulud-worm-npm-supply-chain-compromise)).
