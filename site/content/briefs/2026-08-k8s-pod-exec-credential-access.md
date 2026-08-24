---
title: Kubernetes Pod Exec Sensitive File Access Detection
slug: 2026-08-k8s-pod-exec-credential-access
description: Detection of Kubernetes pod exec sessions accessing sensitive host and in-cluster files used for credential theft and lateral movement.
date: "2026-08-24T15:47:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - kubernetes
  - pod-exec
  - cloud
  - threat-detection
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This detection rule identifies suspicious activity within Kubernetes clusters where a pod 'exec' session is used to access sensitive files, credential stores, or configuration paths.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The intent is to catch interactive or scripted access that often precedes lateral movement, privilege escalation, or credential theft from the node or workload boundary.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
    evidence: Detects Kubernetes pod exec sessions whose decoded command line references high-value host or in-cluster paths.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy ESQL detection rule to SIEM audit log stream
      owner: Detection Engineering
      due: 48h
      evidence: Source provides complete query logic
  mitigation_plan:
    - priority: immediate
      action: Review and restrict RBAC permissions for pod/exec subresource
      owner: Platform Security
      addresses: T1609
      evidence: Source notes that tightening pods exec RBAC is critical for response
---

This alert addresses the abuse of the Kubernetes pod exec API to perform reconnaissance and credential theft. Attackers often leverage legitimate administrative access to interactively or programmatically access sensitive files within a container. This activity frequently precedes lateral movement or privilege escalation. The scope includes access to high-value targets such as mounted service account tokens (including IRSA and Workload Identity), host configuration files (/etc/shadow, /etc/passwd), private keys, keystores, and process environment variables that may contain secrets. The detection focuses on auditing Kubernetes API server logs for exec commands that reference these sensitive paths. Defending against this requires strict RBAC controls for the exec subresource and robust monitoring of audit logs for anomalous administrative access patterns.

## Attack Chain

1. Attacker gains initial access to a Kubernetes cluster via compromised credentials or a vulnerable workload.
2. Attacker enumerates pods and containers to identify targets with sufficient privileges or sensitive mounts.
3. Attacker uses the 'kubectl exec' command or direct Kubernetes API calls to initiate an interactive session inside a container.
4. Attacker executes commands (e.g., cat, grep, ls) to probe for sensitive files or credential material in the container filesystem.
5. Attacker accesses high-value targets such as /var/run/secrets/kubernetes.io/serviceaccount/token or cloud-provider identity tokens.
6. Attacker exfiltrates discovered credentials or tokens to gain higher-level access to the cluster or cloud control plane.
7. Attacker performs further actions such as secret dumping, RBAC modifications, or container breakout to achieve final objectives.

## Impact

Successful exploitation of this technique allows an attacker to steal identity tokens, compromise service accounts, gain persistent access to the Kubernetes control plane, or escalate privileges within the cloud environment. Depending on the stolen credentials, this can lead to full cluster compromise or unauthorized access to external cloud resources (AWS, Azure, GCP).

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Deploy the ESQL detection logic to the SIEM and validate against existing audit logs.
- Implement RBAC controls to restrict 'exec' permissions to only necessary users and automated service identities.
- Review all pods with 'hostPath' mounts or privileged security contexts as these are primary targets for credential exfiltration.
- Establish baseline monitoring for stable automation identities to reduce false positives from diagnostic or monitoring agents.
