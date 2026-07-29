---
title: Suspicious File Creation and Execution within Linux Containers
slug: 2026-07-interactive-file-execution-in-containers
description: An Elastic Defend for Containers rule detects suspicious activity in Linux containers where a process creates a file in a writable directory and immediately executes it, indicating potential hands-on intrusion, container breakout, unauthorized host access, privilege escalation, or evasion of security controls.
date: "2026-07-29T12:52:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - linux
  - execution
  - command-and-control
  - threat-detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This detects activity inside a running Linux container creating a new file and then executing it moments later... Attackers commonly use an `exec` shell into a pod/container to drop a small script or ELF payload... and run it immediately
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Inspect the container’s network activity immediately following execution (DNS lookups, new outbound connections, unusual ports/destinations) to confirm or rule out command-and-control or payload download behavior.
    confidence_band: med
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/execution_interactive_file_creation_followed_by_execution.toml
rules:
  - title: Suspicious Execution from Writable Container Paths
    description: Detects processes executing from common writable temporary or user directories within a Linux container, excluding common package manager activities, which may indicate a dropped and executed malicious payload.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1071
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Elastic Defend for Containers has implemented a new rule to identify interactive malicious activity within Linux-based container environments. This detection focuses on a specific behavioral sequence where an attacker, having gained interactive access to a container (e.g., via `kubectl exec` or `docker exec`), first creates a new file (such as a script or an ELF payload) within a common writable location like `/tmp`, `/var/tmp`, `/dev/shm`, `/root`, or `/home`, and then proceeds to execute it moments later. This pattern is highly indicative of an active intrusion rather than routine automated processes, suggesting an adversary is attempting to establish control, stage a container breakout, gain unauthorized access to the underlying host, escalate privileges, or evade existing security mechanisms. The rule is available from Elastic Stack version 9.3.0 onwards.

## Attack Chain

1. **Initial Access to Container**: An attacker gains interactive shell access to a running Linux container or pod, typically leveraging `kubectl exec` or `docker exec` commands.
2. **Payload Delivery**: The adversary then transfers or creates a malicious script or an ELF executable payload directly into a common writable temporary directory within the container's filesystem, such as `/tmp`, `/var/tmp`, `/dev/shm`, `/root`, or `/home`.
3. **Execution**: Immediately after creation, the attacker executes the newly dropped malicious file to establish persistence or execute initial commands.
4. **Command and Control (C2)**: The executed payload may attempt to establish outbound network connections to attacker-controlled infrastructure for command and control or to download additional stages of malware.
5. **Privilege Escalation / Breakout**: The payload attempts to escalate privileges within the container or exploit vulnerabilities to achieve a container breakout, gaining access to the underlying host system's resources (e.g., `docker.sock`, hostPath mounts, `/proc` probing).
6. **Impact**: The attacker achieves their final objectives, which may include unauthorized host access, data exfiltration, lateral movement to other containers or nodes, or disruption of services.

## Impact

Successful exploitation of this activity can lead to severe consequences for containerized environments and the underlying infrastructure. Attackers can gain unauthorized access to the host system, facilitating container breakouts to compromise other containers, nodes, or even the entire Kubernetes cluster. This can result in data theft, unauthorized resource usage, disruption of critical services, and the establishment of persistent backdoors. The targeted nature of this attack, often involving hands-on-keyboard activity, indicates a high level of threat and potential for significant damage.

## Recommendation

* Deploy the provided Sigma rule to your SIEM to detect suspicious process execution from writable paths within Linux containers.
* Correlate alerts from the Sigma rule with container runtime and Kubernetes audit logs to identify the user, source IP, and mechanism used for interactive sessions.
* Acquire and analyze the newly created and executed files to determine their purpose and malicious nature.
* Implement runtime controls to block execution from writable paths like `/tmp` and `/dev/shm` in containers.
* Restrict interactive `exec`/`attach` access to container environments to a minimal administrative group, enforcing Multi-Factor Authentication (MFA).
* Enforce Pod Security/Admission policies to disallow privileged containers and host mounts that could facilitate container breakouts.
