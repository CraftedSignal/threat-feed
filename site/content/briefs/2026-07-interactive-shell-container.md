---
title: Interactive Shell Spawn Detected in Linux Container Environments
slug: 2026-07-interactive-shell-container
description: An Elastic Defend for Containers rule detects when an interactive shell is spawned inside a running Linux container, indicating a potential container breakout attempt or an attacker's unauthorized access to the underlying host through the execution of shells such as bash, sh, or zsh with interactive flags.
date: "2026-07-29T12:54:53Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - container-security
  - linux
  - execution
  - threat-detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule detects when an interactive shell is spawned inside a running container...focusing on specific process actions and arguments indicative of interactive sessions.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/execution_interactive_shell_spawned_from_inside_a_container.toml
rules:
  - title: Detect Interactive Shell Spawn in Linux Container
    description: Detects the creation of an interactive shell (e.g., bash, sh) within a Linux container, often indicating a container breakout attempt or unauthorized access.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This brief describes a detection rule designed by Elastic for their Defend for Containers solution, focusing on the suspicious spawning of interactive shells within Linux container environments. Threat actors often leverage interactive shells (e.g., bash, sh, zsh) as a post-exploitation technique to establish a persistent presence, gain unauthorized access, or facilitate container breakout attempts. The detection specifically targets scenarios where a shell process, identified by its executable name and the presence of interactive flags like "-i" or "-it" in its command line arguments, is initiated within a container. While legitimate debugging or administration tasks can trigger this alert, its presence warrants immediate investigation as it can signify a critical phase in an attacker's attempt to compromise the container and potentially the host system. This detection is crucial for identifying early stages of container compromise and lateral movement.

## Attack Chain

[The provided source describes a detection rule for specific behavior rather than an end-to-end attack chain. Therefore, a detailed attack chain cannot be constructed.]

## Impact

A successful interactive shell spawn within a container can lead to significant compromises. Attackers can use this foothold to execute arbitrary commands, exfiltrate sensitive data, modify configurations, or deploy additional malicious tools. The primary concern is the potential for container breakout, where the attacker escapes the containerized environment to gain access to the underlying host system, leading to broader infrastructure compromise. This could result in data breaches, denial of service, resource abuse (e.g., cryptocurrency mining), or the establishment of long-term persistence within the organization's cloud or on-premise container infrastructure.

## Recommendation

* Deploy the Sigma rule "Detect Interactive Shell Spawn in Linux Container" to your SIEM, ensuring process creation logs from Linux containers are ingested.
* Review and tune the "Detect Interactive Shell Spawn in Linux Container" rule by creating exceptions for known legitimate users, container IDs, or automated scripts that intentionally spawn interactive shells for debugging or administrative purposes within your development and testing environments.
* Immediately isolate any container that triggers the "Detect Interactive Shell Spawn in Linux Container" rule to prevent further unauthorized access or potential container escape.
* Implement stricter access controls and monitoring on container environments to prevent unauthorized shell access, such as using role-based access controls and enabling audit logging for containers.
* Capture and preserve forensic data from containers that trigger the detection, including logs, process lists, and network activity, to aid in further investigation.
