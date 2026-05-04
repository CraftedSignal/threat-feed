---
title: Kubernetes Pod Exec Sensitive File or Credential Path Access
slug: 2024-01-kubernetes-pod-exec-sensitive-file-access
description: This rule detects Kubernetes pod exec sessions where the decoded command line references sensitive files or paths such as mounted service account tokens, kubelet and control-plane configuration, host identity stores, private keys, and process environment dumps, aiming to identify potential lateral movement, privilege escalation, or credential theft.
date: "2026-05-04T21:42:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - credential-access
  - execution
vendors:
  - Elastic
products:
  - Elastic License v2
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
references:
  - https://attack.mitre.org/techniques/T1552/001/
  - https://attack.mitre.org/techniques/T1552/007/
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1609/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/credential_access_kubernetes_pod_exec_sensitive_file_access.toml
rules:
  - title: Kubernetes Pod Exec Sensitive File Access
    description: Detects Kubernetes pod exec sessions where the command line references sensitive files or paths.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - execution
    techniques:
      - T1552.001
      - T1552.007
      - T1609
    data_sources:
      - process_creation
      - linux
  - title: Kubernetes Pod Exec Accessing Environment Variables
    description: Detects Kubernetes pod exec sessions where the command line attempts to access process environment variables.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - execution
    techniques:
      - T1552
      - T1609
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection identifies Kubernetes pod exec sessions accessing sensitive files or credential paths. The goal is to detect attackers attempting to steal credentials or configuration information from within Kubernetes pods. This often occurs after initial access and may precede lateral movement, privilege escalation, or data exfiltration. The detection focuses on command lines that reference paths related to service account tokens, kubelet configuration, host identity stores, common private keys, keystore extensions, process environment dumps, and configuration files with embedded secrets. The rule is designed to catch both interactive and scripted access, and includes exclusions for benign reads of resolv.conf.

## Attack Chain

1.  Attacker gains initial access to a Kubernetes cluster, potentially through a compromised application or misconfigured service.
2.  Attacker uses `kubectl exec` or similar tools to execute commands within a pod.
3.  The executed command attempts to read sensitive files or directories within the pod's filesystem, such as `/var/run/secrets/kubernetes.io/serviceaccount/token` to obtain the pod's service account token.
4.  The command may also target host-level files if the pod has hostPath mounts or runs in a privileged context, like `/etc/shadow` or `/etc/passwd` for credential access.
5.  The attacker may attempt to dump process environments via `/proc/<pid>/environ` to extract sensitive information stored as environment variables.
6.  The attacker leverages obtained credentials or configuration to move laterally to other pods or nodes within the cluster.
7.  The attacker escalates privileges within the cluster by abusing stolen service account tokens or node credentials.
8.  The final objective is to exfiltrate sensitive data, deploy malicious workloads, or disrupt services within the Kubernetes environment.

## Impact

A successful attack can lead to the compromise of sensitive data, including credentials, configuration files, and application secrets. This can enable attackers to move laterally within the Kubernetes cluster, escalate privileges, and potentially gain control over the entire environment. The severity of the impact depends on the sensitivity of the data exposed and the level of access achieved by the attacker.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect sensitive file access within Kubernetes pod exec sessions.
*   Investigate any alerts triggered by the Sigma rule, focusing on the `Esql.access_type` field to prioritize incidents.
*   Review and tighten RBAC permissions for pod exec to limit access to authorized users and service accounts.
*   Implement admission controls to prevent pods from running in privileged mode or using hostPath mounts unless absolutely necessary.
*   Monitor Kubernetes audit logs for suspicious `kubectl exec` activity, including unusual command lines or access patterns.
*   Regularly rotate Kubernetes service account tokens and other sensitive credentials to minimize the impact of potential breaches.
*   Use the provided Kubernetes audit log query to proactively search for historical instances of sensitive file access.
