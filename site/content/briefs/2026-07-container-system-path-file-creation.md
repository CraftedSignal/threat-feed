---
title: Container Compromise via File Creation in System Binary Locations
slug: 2026-07-container-system-path-file-creation
description: Adversaries leverage tools like wget, curl, or busybox to create files within critical system binary directories such as /etc, /root, /bin, /usr/bin, /usr/local/bin, or /entrypoint inside running Linux containers to establish persistence, execute commands, or evade detection.
date: "2026-07-29T12:53:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container-security
  - linux
  - execution
  - defense-evasion
  - command-and-control
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers commonly gain a shell, then use curl/wget (or a busybox variant) from a writable staging area to drop a new executable into /usr/local/bin or overwrite an entrypoint script to ensure their code runs on start.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Attackers commonly gain a shell, then use curl/wget (or a busybox variant) from a writable staging area to drop a new executable...
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Attackers commonly gain a shell, then use curl/wget (or a busybox variant) from a writable staging area to drop a new executable...
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Adversaries may use these locations to create files that can be used to execute commands on the underlying host, or to evade detection by security controls.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/execution_interactive_file_creation_in_system_binary_locations.toml
rules:
  - title: Detect File Creation in Container System Binary Locations
    description: Detects when a process creates files in critical system binary locations (/etc, /root, /bin, /usr/bin, /usr/local/bin, /entrypoint) within a running Linux container, especially when initiated by common download tools (wget, curl, busybox) or processes launched from temporary directories.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
      - execution
    techniques:
      - T1036
      - T1036.005
      - T1059
      - T1059.004
      - T1071
      - T1105
    data_sources:
      - file_event
      - linux
rules_count: 1
---

This threat involves the creation of new files within critical system binary locations inside running Linux containers by malicious actors. Attackers commonly gain initial access to a container, then use tools like `curl`, `wget`, or `busybox` to download and drop malicious executables, scripts, or configuration files into trusted system paths such as `/etc`, `/root`, `/bin`, `/usr/bin`, `/usr/local/bin`, or `/entrypoint`. This technique is used for various malicious purposes, including establishing persistence, executing arbitrary commands, or evading security controls by masquerading as legitimate system components. The activity often originates from interactive sessions or from processes executed from temporary staging areas like `/tmp`, `/dev/shm`, or `/var/tmp`. Detection of such activity is crucial as it signals a potential compromise of the container and could lead to broader impact on the underlying host or adjacent systems.

## Attack Chain

1. **Initial Container Access**: Adversaries gain unauthorized access to a running Linux container, often exploiting a vulnerable application, misconfigured API endpoints, or exposed credentials.
2. **Container Environment Reconnaissance**: The attacker explores the compromised container's filesystem and environment variables to identify writable directories, available utilities, and potential paths for persistence.
3. **Ingress Tool Transfer (Staging)**: Malicious tools, scripts, or payloads are downloaded into temporary, writable locations within the container, such as `/tmp`, `/dev/shm`, or `/var/tmp`, typically using utilities like `curl` or `wget`.
4. **Defense Evasion & Persistence (Placement)**: The downloaded malicious files are then moved or copied from the temporary staging area into critical system binary locations like `/usr/local/bin`, `/etc`, `/bin`, `/usr/bin`, `/root`, or `/entrypoint`. This action serves to establish persistence, hide malicious components, or ensure execution upon container restart.
5. **Execution of Malicious Payload**: The placed malicious file is executed, either directly by the attacker, triggered through a modified entrypoint script, or initiated through other persistence mechanisms (e.g., cron jobs within the container).
6. **Command and Control / Impact**: The executed payload establishes command and control (C2) communication, performs data exfiltration, crypto-mining, or further compromises the host system or other containers in the environment.

## Impact

Successful exploitation results in unauthorized code execution within a container, potentially leading to container escape, privilege escalation on the underlying host, or compromise of other services. Adversaries can tamper with container execution flow, install persistent backdoors, or exfiltrate sensitive data. If an attacker gains control over system binary locations, they can replace legitimate binaries, inject malicious scripts into startup routines, or establish hidden command and control channels. This can compromise the integrity, confidentiality, and availability of containerized applications and the entire host infrastructure.

## Recommendation

* Deploy the Sigma rule "Detect File Creation in Container System Binary Locations" to your SIEM to identify suspicious file write operations.
* Enable comprehensive file event logging for Linux containers, specifically capturing file creation events and associated process information, to provide the necessary telemetry for the rule.
* Implement runtime security policies for containers to prevent write access to critical system binary locations like `/etc`, `/root`, `/bin`, `/usr/bin`, `/usr/local/bin`, and `/entrypoint`.
* Regularly review container images for deviations from baseline configurations and ensure that containers are running with the least privileges (e.g., as non-root users) and with a read-only root filesystem.
