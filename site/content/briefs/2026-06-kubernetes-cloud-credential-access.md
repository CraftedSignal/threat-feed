---
title: Kubernetes and Cloud Credential Path Access via Process Arguments
slug: 2026-06-kubernetes-cloud-credential-access
description: This rule detects Linux process executions that access high-value Kubernetes service-account material, kubeconfig or node PKI paths, or common cloud files, potentially indicating credential theft within in-cluster and hybrid environments.
date: "2026-06-01T10:10:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - threat-detection
  - kubernetes
  - cloud
  - linux
vendors:
  - Amazon
  - Microsoft
  - Google
  - Atlassian
  - Docker
  - Kubernetes
  - Rancher
products:
  - Amazon EKS
  - Azure
  - gcloud
  - Confluence Data Center
  - Docker
  - Kubernetes
  - K3s
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
references:
  - https://attack.mitre.org/techniques/T1552/
  - https://kubernetes.io/docs/concepts/security/service-accounts/
rules:
  - title: Detect Kubernetes and Cloud Credential Path Access via Process Arguments
    description: Detects processes accessing Kubernetes service account tokens, kubeconfigs, node PKI keys, or cloud configuration files via command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1528
      - T1552
      - T1552.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Kubernetes Admin Configuration File Access
    description: Detects processes attempting to access the Kubernetes admin configuration file, often used for cluster administration.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552
      - T1552.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Azure Access Tokens File Access
    description: Detects processes attempting to access Azure Access Tokens file.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552
      - T1552.001
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This detection identifies Linux processes executing commands that include arguments referencing sensitive Kubernetes and cloud credentials. This includes paths to Kubernetes service account tokens, kubeconfigs, node PKI keys, and common cloud configuration files, such as AWS, Azure, and gcloud credentials. The rule focuses on processes using common file-reading utilities (e.g., cat, head, grep) or running from ephemeral directories (/tmp, /var/tmp), which are frequently used by attackers attempting to steal credentials. This behavior often indicates unauthorized access or lateral movement within a compromised environment, and is critical for detecting in-cluster and hybrid cloud credential theft early in the attack lifecycle.

## Attack Chain

1. An attacker gains initial access to a compromised Linux system, possibly through exploiting a vulnerability or using stolen credentials.
2. The attacker attempts to enumerate accessible resources and identify potential targets, including Kubernetes and cloud credentials.
3. The attacker uses common file-reading utilities such as `cat`, `head`, `grep`, or `find` to locate sensitive files and directories.
4. The attacker executes commands that include arguments referencing well-known paths containing Kubernetes service account tokens, kubeconfigs, or cloud provider credentials (AWS, Azure, gcloud).
5. The attacker may attempt to move these files to a temporary directory such as `/tmp`, `/var/tmp`, or `/dev/shm`.
6. The attacker exfiltrates the stolen credentials using tools like `curl`, `wget`, `scp`, or `rsync`.
7. The attacker uses the stolen credentials to access sensitive Kubernetes resources, cloud services, or other internal systems.
8. The attacker attempts to further expand their access and control within the environment, potentially leading to data exfiltration or other malicious activities.

## Impact

Successful exploitation can lead to unauthorized access to sensitive Kubernetes resources, cloud services, and internal systems. This can result in data breaches, service disruptions, and further lateral movement within the compromised environment. The compromised credentials can be used to create new resources, modify existing configurations, or access sensitive data stored in the cloud. This can have significant financial and reputational damage to the organization.

## Recommendation

*   Enable **Elastic Defend** and/or **Auditd Manager** process telemetry (`logs-endpoint.events.process*`, `logs-auditd_manager.auditd-*`, `auditbeat-*`) with command-line argument capture for exec events as described in the rule setup.
*   Deploy the Sigma rule `Kubernetes and Cloud Credential Path Access via Process Arguments` to your SIEM and tune for your environment, paying close attention to the `false_positives` noted in the rule to avoid alert fatigue.
*   Tune the provided Sigma rule by filtering specific parent processes, images, or automation identities that legitimately access the mentioned paths, as suggested in the `false_positives` section.
*   Review RBAC and secret mount policies for Kubernetes workloads to minimize the potential impact of credential theft, referencing the recommendations in the rule `note` section.
