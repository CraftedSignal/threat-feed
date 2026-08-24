---
title: Detection of Malicious Reverse Shell Patterns in Kubernetes Pod Exec Requests
slug: 2026-08-k8s-pod-exec-reverse-shell
description: Detection of Kubernetes pod execution requests containing suspicious socket and shell redirection patterns indicative of post-exploitation reverse shell establishment.
date: "2026-08-24T15:47:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - cloud
  - execution
  - command-and-control
  - detection
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
    evidence: Flags exec into a pod when the URL-decoded command payload resembles reverse-shell or bind-shell one-liners invocation patterns.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Flags exec into a pod when the URL-decoded command payload resembles reverse-shell or bind-shell one-liners invocation patterns.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1609/
  - https://attack.mitre.org/techniques/T1059/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/execution_kubernetes_pod_exec_potential_reverse_shell.toml
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable Kubernetes API Server Audit logging and stream to SIEM
      owner: SOC
      due: 48h
      evidence: Required for visibility into pod exec events
  hunt_leads:
    - lead: Identify all recent pod exec requests from non-human service accounts
      technique_id: T1609
      data_needed:
        - Kubernetes Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Anomalous exec patterns are primary indicator of API misuse
---

This threat brief focuses on detecting unauthorized interactive access within Kubernetes clusters via the 'exec' subresource. Threat actors often leverage the Kubernetes API to execute commands within running containers to establish persistent or interactive command-and-control channels. The analyzed detection logic monitors Kubernetes audit logs for specific command-line idioms associated with reverse and bind shells, such as the use of `/dev/tcp`, `netcat`, `socat`, and various scripting language socket libraries. This behavior is a common indicator of post-exploitation movement where an attacker, having gained access to the Kubernetes API, attempts to escalate their foothold by transitioning from a single container execution to a persistent shell session. Defenders should monitor for these patterns to identify unauthorized container administration and potential command-and-control activity.

## Attack Chain

1. Attacker gains authentication to the Kubernetes API server (e.g., via compromised kubeconfig, service account token, or SSRF).
2. Attacker performs enumeration to identify pods and containers within the cluster.
3. Attacker identifies a target container for exploitation.
4. Attacker invokes the `kubectl exec` command or makes a direct REST API call to the pod's 'exec' subresource.
5. The API request URI is crafted to include a shell payload (e.g., `bash -i >& /dev/tcp/...`).
6. The container executes the malicious payload, which initiates an outbound connection to an attacker-controlled listener.
7. A reverse shell is established, granting the attacker interactive access to the container environment.
8. Attacker proceeds to lateral movement or data exfiltration from the compromised container.

## Impact

Successful exploitation allows for unauthorized interactive shell access to containerized workloads, enabling attackers to execute arbitrary code, steal secrets from the container filesystem or environment variables, and facilitate lateral movement throughout the cluster. Impact can range from individual workload compromise to full cluster persistence depending on the privileges assigned to the accessed pod or service account.

## Recommendation

- Implement the detection logic described in the provided audit rule to monitor for suspicious command patterns within `exec` requests.
- Review all users and service accounts with the ability to execute commands in pods (pods/exec permissions) and enforce the principle of least privilege.
- Baseline authorized container image commands and block unauthorized binaries like `socat` or `nc` from being executed in production containers.
- Enable Kubernetes API Server Audit logging to a centralized SIEM to provide the telemetry required for detecting these 'exec' patterns.
- Deploy automated responses to terminate suspicious `exec` sessions identified by the monitoring logic.
