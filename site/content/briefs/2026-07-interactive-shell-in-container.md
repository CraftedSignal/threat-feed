---
title: Interactive Shell Session Detected in Container
slug: 2026-07-interactive-shell-in-container
description: This detection rule targets the execution of interactive shell sessions within Linux containers, often initiated by an attacker using commands like `kubectl exec`, to identify potential compromise attempts or unauthorized access leading to container breakout or further environmental compromise.
date: "2026-07-29T12:51:17Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - container
  - linux
  - elastic-defend-for-containers
  - threat-detection
  - execution
  - investigation-guide
vendors:
  - Elastic
  - Kubernetes
products:
  - Elastic Defend for Containers
  - Kubernetes
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Using the 'exec' command in a pod allows a user to establish a temporary shell session and execute any process/command inside the container.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
    evidence: This rule detects 'exec' events launched against a container using the 'exec' command.
    confidence_band: high
references:
  - https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/
  - https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/
rules:
  - title: Interactive Shell in Container Detected
    description: Detects the creation of interactive shell processes (e.g., bash, sh, zsh) within Linux container environments, indicative of an attacker establishing an interactive session for reconnaissance or further compromise. This rule aligns with Elastic Defend for Containers detection.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1609
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

The Elastic Defend for Containers solution detects `exec` events that establish interactive shell sessions within Linux-based containers. An attacker, having gained initial access to a container orchestration environment, can leverage commands such as `kubectl exec` to run interactive shells like `bash`, `sh`, or `zsh` inside a target container. This grants them real-time command execution capabilities, allowing for exploration, privilege escalation, data exfiltration, or attempts at container breakout to the host system or other containers. The detection specifically focuses on processes identified as the initial process of an interactive shell session within a container. While such activity can be legitimate for debugging or administration, it represents a significant security risk if unauthorized. This threat is relevant to organizations utilizing containerized applications, particularly those running on Kubernetes or similar orchestration platforms.

## Attack Chain

1. **Initial Access to Cluster:** An attacker gains unauthorized access to a Kubernetes cluster or container orchestration environment through compromised credentials, exposed APIs, or misconfigurations.
2. **Container Enumeration:** The attacker enumerates running pods and containers within the cluster to identify suitable targets for interactive access.
3. **Interactive Shell Execution:** The attacker uses `kubectl exec -i -t [pod_name] -- [shell_command]` (e.g., `bash`, `sh`) to establish an interactive shell session directly inside a targeted container.
4. **Container Reconnaissance:** Within the interactive shell, the attacker executes commands (e.g., `ls`, `pwd`, `env`, `cat /etc/passwd`) to understand the container's environment, configuration, and mounted volumes.
5. **Malicious Tool Deployment/Execution:** The attacker downloads or executes additional malicious scripts or binaries within the container to further compromise it, search for sensitive data, or establish persistence.
6. **Container Breakout Attempt:** The attacker exploits misconfigurations or vulnerabilities (e.g., insecure mounts, privileged containers) to escape the container's isolation and gain access to the underlying host or other containers.
7. **Lateral Movement/Impact:** Successful breakout allows the attacker to move laterally across the infrastructure, elevate privileges, exfiltrate sensitive data, or deploy further malware like ransomware.

## Impact

Successful exploitation of unauthorized interactive shell access to a container can lead to severe consequences, ranging from the immediate compromise of the container itself to broader system-wide impact. Attackers can exfiltrate sensitive data stored within the container or accessible via its mounted volumes. They can also establish persistence mechanisms, pivot to other containers, or achieve a container breakout, gaining control over the underlying host. This could affect the integrity and confidentiality of applications and data, disrupt services, or lead to unauthorized resource utilization (e.g., for cryptocurrency mining). The direct impact can involve intellectual property theft, customer data exposure, or complete system takeover, with potential financial, reputational, and regulatory repercussions.

## Recommendation

* **Deploy** the Sigma rule "Interactive Shell in Container Detected" to your SIEM system to detect `exec` events of common shells within your Linux container environments.
* **Review** `process_creation` logs for suspicious shell executions; investigate the `container.id`, `process.entry_leader.same_as_process` (if available in your logs), and associated user activities to differentiate legitimate administrative tasks from malicious activity.
* **Implement** strict Role-Based Access Control (RBAC) in Kubernetes and other container orchestration platforms to limit who can use `kubectl exec` and under what conditions.
* **Configure** exceptions for known legitimate administrative or debugging sessions, as outlined in the `falsepositives` section of the Sigma rule, to reduce alert fatigue.
* **Audit** and **monitor** all `kubectl exec` commands and interactive shell sessions within containers, correlating them with user activity logs to identify the responsible user or service account.
