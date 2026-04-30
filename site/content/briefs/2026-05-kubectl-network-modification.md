---
title: Kubectl Network Configuration Modification
slug: 2026-05-kubectl-network-modification
description: This rule detects potential kubectl network configuration modification activity by monitoring for process events where the kubectl command is executed with arguments that suggest an attempt to modify network configurations in Kubernetes, potentially leading to unauthorized access or data exfiltration.
date: "2026-04-01T14:16:09Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - kubectl
  - kubernetes
  - command_and_control
  - network_configuration
  - linux
  - macos
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_kubectl_networking_modification.toml
  - https://attack.mitre.org/techniques/T1090/
  - https://attack.mitre.org/techniques/T1572/
  - https://attack.mitre.org/tactics/TA0011/
rules:
  - title: Detect Kubectl Port Forwarding from Suspicious Parent Process
    description: Detects kubectl port-forward commands executed from suspicious parent processes like shell scripts in /tmp or /var/tmp.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1090
    data_sources:
      - process_creation
      - linux
  - title: Detect Kubectl Proxy Command Execution
    description: Detects execution of 'kubectl proxy' command which can be used for unauthorized access to the Kubernetes API server.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1090
    data_sources:
      - process_creation
      - linux
  - title: Detect Kubectl Expose Command Execution
    description: Detects execution of 'kubectl expose' command which can be used to create new services and potentially expose unintended access points.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1572
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This detection rule identifies potential malicious activity involving the `kubectl` command-line tool, specifically focusing on modifications to network configurations within Kubernetes environments. The rule monitors for `kubectl` commands executed with arguments like "port-forward", "proxy", or "expose," which can be used to manipulate network settings. The activity is considered suspicious when initiated from atypical parent processes or directories, such as temporary folders or user home directories. This behavior might indicate an adversary attempting to establish unauthorized access channels or exfiltrate sensitive data. The rule is designed to work with endpoint detection and response (EDR) solutions like Elastic Defend, Crowdstrike, SentinelOne, and cloud workload protection platforms. The rule was last updated on March 30, 2026, and is intended for use in production environments.

## Attack Chain

1. An attacker gains initial access to a system with `kubectl` installed and configured to interact with a Kubernetes cluster.
2. The attacker executes the `kubectl` command with arguments like `port-forward` to create a local port that forwards traffic to a service or pod within the cluster.
3. The attacker uses `kubectl proxy` to create a proxy server that allows them to access the Kubernetes API server from their local machine.
4. The attacker employs `kubectl expose` to create a new service that exposes a deployment, replication controller, or pod as a new Kubernetes service, potentially opening up unintended access points.
5. The attacker may execute these commands from a shell like `bash`, or from a script located in a temporary directory like `/tmp/` or `/var/tmp/`, to evade detection.
6. The attacker leverages the modified network configurations to establish unauthorized access to sensitive services or data within the Kubernetes cluster.
7. The attacker may use the proxied or forwarded connections to exfiltrate data from the cluster to an external location.

## Impact

Successful exploitation via `kubectl` network configuration modification can lead to unauthorized access to sensitive data and services within a Kubernetes cluster. This can result in data breaches, service disruptions, and lateral movement within the cluster. The low severity score suggests that while the risk exists, the impact might be limited if proper Kubernetes security best practices are followed. The rule aims to detect these actions early, preventing potential damage to the cluster.

## Recommendation

*   Enable Elastic Defend integration or equivalent EDR solutions to monitor process execution and network connections (`Data Source: Elastic Defend`, `Data Source: Crowdstrike`, `Data Source: SentinelOne`).
*   Deploy the provided Sigma rule to detect suspicious `kubectl` commands with network-related arguments (`rules` section). Tune the rule based on your environment to minimize false positives.
*   Investigate any alerts generated by the Sigma rule, focusing on the parent process and the command-line arguments of the `kubectl` command (`rules` section, `Resources: Investigation Guide`).
*   Implement enhanced monitoring and logging for `kubectl` activities and network configuration changes within the Kubernetes cluster to proactively detect and respond to similar threats in the future (`Resources: Investigation Guide`).
