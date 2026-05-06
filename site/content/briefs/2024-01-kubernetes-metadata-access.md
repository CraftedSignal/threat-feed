---
title: Kubernetes Pod Exec Cloud Instance Metadata Access
slug: 2024-01-kubernetes-metadata-access
description: Detection of Kubernetes pod exec sessions accessing cloud instance metadata endpoints, indicating potential credential theft from AWS, GCP, or Azure.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - cloud
  - credential_access
  - execution
vendors:
  - AWS
  - Google
  - Azure
products:
  - AWS IMDS
  - GCP Compute Metadata
  - Azure IMDS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
references:
  - https://attack.mitre.org/techniques/T1552/005/
  - https://hardenedsecurity.io/blog/aws-imds-vulnerabilities-and-mitigations/
rules:
  - title: Kubernetes Pod Exec IMDS Access
    description: Detects Kubernetes pod exec sessions accessing cloud instance metadata endpoints.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - execution
    techniques:
      - T1552.005
      - T1609
    data_sources:
      - auditd
      - linux
  - title: Kubernetes Pod Exec with Potential Credential Theft
    description: Detects Kubernetes pod exec sessions accessing cloud instance metadata endpoints with credential theft patterns.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - execution
    techniques:
      - T1552.005
      - T1609
    data_sources:
      - auditd
      - linux
rules_count: 2
---

This alert focuses on detecting Kubernetes pod exec sessions that attempt to access cloud instance metadata endpoints. The activity is flagged when the decoded command line of a pod exec session contains references to cloud instance metadata services across AWS, GCP, and Azure. Attackers may exploit this to harvest role credentials, tokens, or instance attributes from the underlying node or hypervisor. This is a high-risk behavior because it can expose short-lived cloud credentials to code running inside a container, particularly concerning in multi-tenant and regulated environments. This detection classifies the cloud target and whether the command indicates credential theft or reconnaissance.

## Attack Chain

1.  Attacker gains initial access to a Kubernetes cluster.
2.  Attacker identifies a vulnerable pod within the cluster.
3.  The attacker uses `kubectl exec` to gain shell access to the pod.
4.  Inside the pod, the attacker crafts a command-line request targeting the cloud instance metadata service (IMDS) endpoint.
5.  The command, often using `curl` or `wget`, attempts to retrieve sensitive information such as IAM roles, tokens, or instance attributes.
6.  The IMDS responds with the requested data, which may include credentials or configuration details.
7.  The attacker exfiltrates the stolen credentials or uses them to escalate privileges within the cloud environment.
8.  Attacker uses the harvested credentials to move laterally, compromise other cloud resources, or exfiltrate sensitive data.

## Impact

Compromised credentials can lead to unauthorized access to sensitive data, lateral movement within the cloud environment, and potential data exfiltration. A successful attack could impact multiple organizations sharing the same Kubernetes cluster. The impact could include financial losses, reputational damage, and regulatory fines, depending on the type of data compromised and the extent of the breach.

## Recommendation

*   Deploy the Sigma rule `Kubernetes Pod Exec IMDS Access` to detect suspicious command-line activity within Kubernetes pods.
*   Block access to the cloud instance metadata endpoints (169.254.169.254) from within Kubernetes pods using network policies.
*   Regularly review and tighten RBAC permissions related to `pods/exec` to limit the ability of attackers to gain shell access.
*   Monitor cloud audit logs for suspicious STS or token issuance events correlated with Kubernetes pod exec events.
*   Implement workload identity solutions to avoid the need to expose instance metadata to pods.
*   Baseline approved images and tune exclusions narrowly to avoid false positives.
