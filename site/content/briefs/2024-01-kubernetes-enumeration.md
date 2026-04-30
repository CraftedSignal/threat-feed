---
title: Kubernetes Cluster Enumeration via Audit Logs
slug: 2024-01-kubernetes-enumeration
description: Attackers attempt to enumerate and discover sensitive information within a Kubernetes cluster by leveraging common shells, utilities, and specialized tools, as reflected in audit logs.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - enumeration
  - cloud
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1609
    technique_name: Container and Resource Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Cloud Account Discovery
references:
  - https://www.nccgroup.com/research/detection-engineering-for-kubernetes-clusters/
  - https://github.com/trufflesecurity/trufflehog
  - https://github.com/corneliusweig/rakkess
rules:
  - title: Kubernetes API Shell Execution via Audit Logs
    description: Detects attempts to execute shells within Kubernetes pods via the audit log, indicating potential enumeration or code execution attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1610
    data_sources:
      - kubernetes
      - audit
  - title: Kubernetes API Tool Usage via Audit Logs
    description: Detects the use of common tools like curl, kubectl, or wget within Kubernetes pods via audit logs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1105
    data_sources:
      - kubernetes
      - audit
  - title: Kubernetes Reconnaissance Tools via User Agent
    description: Detects reconnaissance activity using tools like Rakkess (access_matrix), TruffleHog, AzureHound, and MicroScanner based on the User-Agent string in Kubernetes audit logs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595
    data_sources:
      - kubernetes
      - audit
rules_count: 3
---

Attackers are increasingly targeting Kubernetes environments to gain unauthorized access and extract sensitive information. This activity often begins with enumeration and reconnaissance to map out the cluster's configuration, identify potential vulnerabilities, and locate valuable secrets. This involves the use of standard command-line tools and specialized Kubernetes utilities. Audit logs provide a valuable record of these enumeration attempts, particularly API requests containing shell commands, file transfer utilities, or tools like Rakkess and TruffleHog. This activity is typically aimed at reconnaissance, secret harvesting, or code execution within the cluster. Detecting these patterns in audit logs is critical for identifying and responding to potential breaches.

## Attack Chain

1.  Attacker gains initial access to a system with Kubernetes API access, potentially through compromised credentials or a vulnerable application.
2.  The attacker authenticates to the Kubernetes API server.
3.  The attacker sends a request to the Kubernetes API to execute a shell within a pod, such as `/bin/bash` or `/bin/sh`, potentially URL-encoded.
4.  The attacker uses `kubectl` within a pod to gather information about cluster resources, such as pods, services, and deployments.
5.  The attacker attempts to download tools like `curl` or `wget` into a pod to facilitate further reconnaissance or lateral movement.
6.  The attacker uses tools like `Rakkess` to enumerate role-based access control (RBAC) permissions to identify potential privilege escalation paths.
7.  The attacker deploys `TruffleHog` to scan pod environments for exposed secrets, such as API keys and passwords.
8.  The attacker exfiltrates gathered information and secrets or uses the gained access for lateral movement within the cluster or connected networks.

## Impact

Successful enumeration of a Kubernetes cluster can provide attackers with detailed information about the cluster's architecture, deployed applications, and security configurations. This allows attackers to identify vulnerabilities, escalate privileges, and gain access to sensitive data, such as API keys, passwords, and other secrets. This can lead to data breaches, service disruptions, and compromised infrastructure. The impact can range from a limited data exposure to a full-scale compromise of the entire Kubernetes environment and connected cloud resources.

## Recommendation

*   Deploy the "Kubernetes Potential Enumeration Activity" Sigma rule to your SIEM to detect suspicious API requests containing shell commands, file transfer utilities, or specialized tools (Sigma rule).
*   Investigate any alerts triggered by the Sigma rule to determine the scope and impact of the potential enumeration activity.
*   Review and harden RBAC configurations to minimize the potential for privilege escalation (attack.t1609).
*   Implement strict network segmentation to limit lateral movement within the cluster and connected networks.
*   Regularly scan pods for exposed secrets using dedicated secret scanning tools and enforce secure secret management practices.
*   Monitor Kubernetes audit logs for unusual or unauthorized API activity (logsource: kubernetes, service: audit).
