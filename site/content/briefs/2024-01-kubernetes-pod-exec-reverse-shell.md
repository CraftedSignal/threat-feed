---
title: Kubernetes Pod Exec Potential Reverse Shell Activity Detected
slug: 2024-01-kubernetes-pod-exec-reverse-shell
description: This rule flags potential reverse shell activity via kubectl exec commands in Kubernetes pods by detecting specific shell and socket idioms within URL-decoded command payloads in Kubernetes audit logs, indicating post-exploitation interactive access and command-and-control.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - reverse_shell
  - execution
  - command_and_control
vendors:
  - Elastic
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
references:
  - https://attack.mitre.org/techniques/T1609/
  - https://attack.mitre.org/techniques/T1059/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/execution_kubernetes_pod_exec_potential_reverse_shell.toml
rules:
  - title: Kubernetes Pod Exec Reverse Shell - Netcat
    description: Detects reverse shell attempts using netcat within Kubernetes pod exec commands.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059
      - T1609
    data_sources:
      - webserver
      - linux
  - title: Kubernetes Pod Exec Reverse Shell - Dev TCP
    description: Detects reverse shell attempts using /dev/tcp within Kubernetes pod exec commands.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059
      - T1609
    data_sources:
      - webserver
      - linux
  - title: Kubernetes Pod Exec Reverse Shell - Socat
    description: Detects reverse shell attempts using socat within Kubernetes pod exec commands.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059
      - T1609
    data_sources:
      - webserver
      - linux
rules_count: 3
---

This detection identifies attempts to establish reverse shells or bind shells within Kubernetes pods. The rule analyzes Kubernetes audit logs, specifically targeting `kubectl exec` commands where a user is attempting to execute commands inside a container. By decoding the URL-encoded command parameters and searching for known reverse shell patterns (e.g., usage of `/dev/tcp`, `nc -e`, `socat`), the rule aims to detect unauthorized interactive access and command-and-control activity originating from compromised pods. This activity is often indicative of post-exploitation behavior, where an attacker seeks to gain persistent access to the Kubernetes cluster. The rule is based on the Elastic detection rule released on 2026-04-23. It is critical to investigate these alerts promptly, as successful reverse shell establishment can lead to data exfiltration, lateral movement within the cluster, and further compromise of sensitive resources.

## Attack Chain

1. An attacker gains initial access to a Kubernetes cluster, potentially through a vulnerability in an application running within a pod, or by compromising a user's credentials.
2. The attacker uses `kubectl exec` to execute a command within a target pod. The command is embedded within the `requestURI` parameter, URL-encoded to evade basic detection.
3. The `requestURI` includes the `command=` parameter, followed by a string containing shell commands designed to initiate a reverse or bind shell.
4. The malicious command utilizes utilities such as `nc`, `socat`, or `bash` with redirection to `/dev/tcp` to establish a network connection back to the attacker's controlled machine.
5. The reverse shell connects back to the attacker, providing interactive command execution within the compromised pod.
6. The attacker uses the reverse shell to perform reconnaissance, discover sensitive information, and potentially escalate privileges within the pod.
7. The attacker might attempt to move laterally to other pods or nodes within the cluster, leveraging stolen credentials or exploiting further vulnerabilities.
8. The attacker achieves their objective, which may include data exfiltration, deployment of malicious containers, or disruption of services.

## Impact

A successful reverse shell attack within a Kubernetes cluster can have severe consequences. Attackers can gain unauthorized access to sensitive data, compromise critical applications, and disrupt services. Lateral movement within the cluster can lead to widespread compromise, potentially affecting numerous pods and nodes. The lack of proper monitoring and alerting for `kubectl exec` commands can allow attackers to operate undetected for extended periods, increasing the potential for significant damage. The financial impact can range from tens of thousands to millions of dollars, depending on the severity of the breach and the value of the compromised data.

## Recommendation

*   Deploy the "Kubernetes Pod Exec Potential Reverse Shell" Sigma rule to your SIEM and tune for your environment to detect malicious `kubectl exec` commands.
*   Enable Kubernetes audit logging to capture `kubectl exec` events and ensure that the audit logs are ingested into your SIEM.
*   Implement network policies to restrict outbound connections from pods, limiting the ability of attackers to establish reverse shells.
*   Monitor Kubernetes audit logs for suspicious user activity, such as unusual API calls or access to sensitive resources.
*   Regularly review and update RBAC (Role-Based Access Control) policies to minimize the privileges assigned to users and service accounts, reducing the attack surface.
*   Implement the provided regex pattern in the Sigma rule within your existing detection logic, ensuring adequate coverage of reverse shell attempts.
