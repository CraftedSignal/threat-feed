---
title: Kubectl Network Configuration Modification
slug: 2026-05-kubectl-network-modification
description: This rule detects potential kubectl network configuration modification activity by monitoring for process events where the kubectl command is executed with arguments that suggest an attempt to modify network configurations in Kubernetes, potentially leading to unauthorized access or data exfiltration.
date: "2026-04-01T14:16:09Z"
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

This detection rule identifies potential malicious activity involving the `kubectl` command-line tool, specifically focusing on modifications to network configurations within Kubernetes environments. The rule monitors for `kubectl` commands executed with arguments like "port-forward", "proxy", or "expose," which can be used to manipulate network settings. The activity is considered suspicious when initiated from atypical parent processes or directories, such as temporary folders or user home…
