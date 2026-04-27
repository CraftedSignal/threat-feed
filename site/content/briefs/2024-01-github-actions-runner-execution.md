---
title: Execution via GitHub Actions Runner
slug: 2024-01-github-actions-runner-execution
description: Adversaries compromising GitHub Actions workflows can execute arbitrary commands on runner hosts, leading to code execution, reconnaissance, credential harvesting, or network exfiltration.
date: "2024-01-02T10:00:00Z"
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

This threat focuses on the exploitation of GitHub Actions runners by malicious actors. By gaining the ability to modify or trigger workflows in a linked GitHub repository, attackers can execute arbitrary commands on the runner host. The attack leverages the `Runner.Worker` process or shell interpreters launched via runner entrypoint scripts. Successful exploitation can lead to malicious workflow activity, including code execution, reconnaissance, credential harvesting, and network exfiltration…
