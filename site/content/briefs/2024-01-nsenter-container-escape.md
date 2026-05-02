---
title: Nsenter Execution with Target Flag Inside Container
slug: 2024-01-nsenter-container-escape
description: The rule detects nsenter executions from inside a monitored Linux container that include a namespace target flag (-t or --target), which can be abused to escape container isolation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - container
  - privilege-escalation
  - linux
vendors:
  - Elastic
products:
  - Defend for Containers
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
references:
  - https://attack.mitre.org/techniques/T1611/
  - https://man7.org/linux/man-pages/man1/nsenter.1.html
rules:
  - title: Detect Nsenter Container Escape
    description: Detects nsenter executions with target flag inside container which could indicate container escape attempt
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
  - title: Detect Nsenter by Process Name
    description: Detects nsenter executions by process name with target flag inside container which could indicate container escape attempt
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection identifies the execution of `nsenter` within a Linux container, specifically when the `-t` or `--target` flag is used. This flag indicates an attempt to enter another process or namespace context. Attackers can exploit this capability, especially when combined with privileged mounts, exposed PIDs, or shared namespaces, to escape the container and pivot to the host system. This activity can lead to privilege escalation and further compromise of the underlying infrastructure. The detection is relevant for environments using Elastic Defend for Containers.

## Attack Chain

1. An attacker gains initial access to a container, possibly through exploiting a vulnerability in a containerized application.
2. The attacker identifies a container with weak configurations, such as exposed PIDs, shared namespaces, or privileged mounts.
3. The attacker executes `nsenter` with the `-t` or `--target` flag, specifying a target PID or namespace.
4. The `nsenter` command joins the target namespace (mount, network, PID, user, or IPC) based on specified flags (`-m`, `-n`, `-p`, `-U`, or `-i`).
5. The attacker gains access to the host system's resources or processes due to the namespace sharing or privileged access.
6. The attacker escalates privileges on the host system, potentially gaining root access.
7. The attacker pivots to other containers or the host infrastructure, expanding their control.
8. The attacker achieves their final objective, such as data exfiltration, system disruption, or deploying malware on the host.

## Impact

A successful container escape can allow an attacker to compromise the underlying host system. This can lead to the compromise of other containers running on the same host, as well as sensitive data stored on the host system. The impact can range from data breaches to complete infrastructure takeover. If the host is a node in a Kubernetes cluster, the attacker might be able to compromise the entire cluster.

## Recommendation

*   Deploy the Sigma rule `Detect Nsenter Container Escape` to your SIEM and tune for your environment to detect suspicious `nsenter` executions within containers.
*   Review container configurations and enforce least privilege to prevent unauthorized namespace sharing and privileged mounts.
*   Monitor container logs for `nsenter` executions with target flags, as indicated by the log source `logs-cloud_defend.process*` and the query in this brief.
*   Restrict the use of hostPath volumes and other sensitive mounts within container deployments.
*   Reduce recurrence by avoiding host namespace sharing, restricting hostPath and sensitive mounts, and blocking unnecessary capabilities.
