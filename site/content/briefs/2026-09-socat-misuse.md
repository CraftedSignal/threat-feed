---
title: Detection of Malicious Socat Listener Configurations
slug: 2026-09-socat-misuse
description: Adversaries leverage the socat utility to establish bind shells or facilitate remote command execution by binding executables to network listeners, a technique increasingly observed in macOS post-exploitation scenarios.
date: "2026-09-07T04:41:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - macos
  - linux
  - post-exploitation
  - lateral-movement
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The following analytic detects the execution of the socat utility with command-line arguments that configure a TCP or OpenSSL listener and bind an executable to incoming connections.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: Socat is a legitimate network utility, but this behavior may be used to expose executables, establish bind shells, facilitate remote command execution, or support lateral movement.
    confidence_band: high
rules:
  - title: Detect Socat Listener Binding Executable
    description: Detects the execution of socat with command-line arguments that configure a listener and bind an executable, which is indicative of bind shell or remote command execution attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor for socat abuse.
      owner: Detection Engineering
      due: 48h
      evidence: Source document identifies this as a TTP analytic.
  hunt_leads:
    - lead: Search endpoint logs for command lines containing socat combined with exec and listen flags.
      technique_id: T1059
      data_needed:
        - Process command line arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source search query targets these specific parameters.
---

The socat utility is a powerful, multi-purpose relay tool capable of bidirectional data transfer between various address types. While legitimate for network troubleshooting and debugging, its ability to execute system binaries upon receiving network connections makes it a prime target for post-exploitation abuse. Adversaries use socat to configure TCP or OpenSSL listeners that automatically route incoming traffic to local processes or shell environments, effectively creating backdoors or bind shells. This behavior is particularly dangerous as it enables remote command execution and lateral movement without requiring complex custom malware. Defenders should prioritize monitoring for the specific combination of 'exec:' and 'listen:' command-line arguments in process logs.

## Attack Chain

1. Initial access established through phishing or exploitation of a local vulnerability.
2. Adversary identifies the socat utility on the target system.
3. Adversary executes socat with arguments configuring a listener (e.g., tcp-listen).
4. Adversary binds a system shell or script to the listener using the exec option.
5. Attacker connects remotely to the designated listener port.
6. The socat process spawns the bound executable to handle the incoming traffic.
7. Adversary gains a bind shell or remote execution capabilities on the host.

## Impact

Successful abuse of socat in this manner grants an adversary persistent or ad-hoc remote command execution capabilities. This facilitates further lateral movement, exfiltration of sensitive data, and potential full system compromise. The technique is frequently observed in macOS post-exploitation activity where native tools are weaponized to minimize the footprint of malicious binaries.

## Recommendation

* Deploy process-level auditing using Osquery or Sysmon for Linux to capture command-line arguments for all executed processes.
* Implement the suggested Sigma rule to identify command lines containing both 'listen' and 'exec' strings within the same socat process invocation.
* Investigate instances of socat execution originating from unexpected parent processes or service accounts.
* Restrict the execution of network utilities to authorized administrators and specific, hardened service accounts.
