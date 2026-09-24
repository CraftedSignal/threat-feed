---
title: Potential Netcat Reverse Shell Execution
slug: 2026-09-netcat-reverse-shell
description: Detection of Linux process creation events where Netcat is utilized with command execution flags to spawn interactive reverse shells.
date: "2026-09-24T12:13:12Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects execution of netcat with the -e or -c flags followed by common shells, which are commonly used to spawn reverse shells.
    confidence_band: high
rules:
  - title: Detect Potential Netcat Reverse Shell Execution
    description: Detects execution of netcat variants with the -e or -c flags followed by common shell binaries to spawn a reverse shell.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to SIEM and monitor for occurrences.
      owner: Detection Engineering
      due: 48h
      evidence: Rule definition in source material.
  mitigation_plan:
    - priority: medium_term
      action: Remove or restrict access to the -e flag for Netcat binaries where not required for administrative tasks.
      owner: IT Operations
      addresses: T1059
      evidence: General security best practice for reducing attack surface.
---

This brief focuses on the detection of malicious use of the Netcat utility on Linux systems to establish reverse shell connections. Attackers frequently leverage Netcat's ability to execute commands and redirect input/output streams to network sockets. By invoking Netcat with specific flags such as -e (execute) or -c (command), attackers can bind a local shell (e.g., bash, sh, or zsh) to a remote listener, granting unauthorized remote access. This technique is a common post-exploitation pattern observed in many intrusion scenarios, enabling persistent command-and-control capabilities. Detection relies on monitoring command-line arguments of common Netcat binaries (nc, ncat, netcat.traditional) for these specific execution flags and shell paths.

## Attack Chain

1. Attacker performs initial reconnaissance to identify open ports or services.
2. Attacker uploads or identifies a pre-installed Netcat binary on the target Linux system.
3. Attacker sets up a remote listener on their controlled infrastructure to capture the connection.
4. Attacker executes the Netcat binary on the target host using command-line arguments like '-e /bin/bash'.
5. The Netcat process initiates an outbound TCP connection to the attacker's listener.
6. The standard input, output, and error streams of the bash shell are redirected through the established network socket.
7. The attacker interacts with the target system via the remote shell to execute system commands, exfiltrate data, or deploy secondary payloads.

## Impact

Successful exploitation allows an attacker to gain interactive remote command execution on the target Linux system. This can lead to full system compromise, lateral movement within the network, data exfiltration, or the deployment of additional malicious tools such as ransomware or backdoors.

## Recommendation

Deploy the provided Sigma rule to your Linux process monitoring pipeline to detect unauthorized Netcat usage. If your environment requires legitimate administrative use of Netcat with shell execution, consider creating an allowlist based on specific user accounts or authorized script paths.

* Enable Linux process-creation auditing (e.g., auditd, Sysmon for Linux) to capture the CommandLine field.
* Implement alerting for the execution of Netcat with -e or -c flags.
* Audit all shell access patterns to identify unauthorized remote interactive sessions.
