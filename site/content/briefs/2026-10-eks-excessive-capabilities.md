---
brief_id: brief-2026-10-21-eks-excessive-capabilities
event_id: brief-2026-10-21-eks-excessive-capabilities
revision: 1
activity_at: "2026-10-21T13:59:44Z"
title: 'AWS EKS: Deployment of containers with excessive Linux capabilities'
slug: 2026-10-eks-excessive-capabilities
description: Detection logic for identifying AWS EKS pod deployments that request high-risk Linux capabilities capable of facilitating container escapes and host-level privilege escalation.
date: "2026-10-21T13:59:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - cloud
  - kubernetes
  - aws
  - container-escape
vendors:
  - Amazon
products:
  - EKS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: The capabilities detected in this rule have been used in container escapes to the host machine.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1610
    technique_name: Deploy Container
    evidence: An attacker with the ability to deploy a container with added capabilities could use this for further execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1610
    technique_name: Deploy Container
    evidence: Added capabilities entitle containers in a pod with additional privileges that can be used to change core processes.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/privilege_escalation_container_created_with_excessive_linux_capabilities_aws_eks.toml
  - https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container
  - https://man7.org/linux/man-pages/man7/capabilities.7.html
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Cloud Security
  immediate_actions:
    - action: Enable EKS audit log collection via AWS integration and deploy monitoring for excessive capability requests.
      owner: Detection Engineering
      due: 48h
      evidence: Rule metadata requires aws.eks_audit data stream.
  mitigation_plan:
    - priority: medium_term
      action: Implement Pod Security Admission to restrict use of privileged capabilities across all namespaces.
      owner: Cloud Security
      addresses: Container Escape risk
      evidence: Response and remediation documentation.
---

This brief outlines a detection capability for monitoring AWS EKS control-plane audit logs for the creation of pods with dangerously permissive Linux capabilities. Added capabilities - such as CAP_SYS_ADMIN, CAP_NET_ADMIN, or CAP_BPF - grant threads privileged access that can be abused to bypass security boundaries, modify kernel-level processes, or perform container breakouts. This detection is intended for identifying unauthorized or anomalous container deployments that deviate from the principle of least privilege.

## Impact

Containers with excessive capabilities can be leveraged to escape to the host machine, intercept network traffic within the cluster, perform unauthorized system administration tasks, or load malicious kernel modules.

## Recommendation

- Enable EKS control-plane audit logs and stream them to your security information and event management (SIEM) system using the AWS integration.
- Audit existing workloads to identify containers running with added capabilities and verify their business necessity.
- Implement Pod Security Admission (PSA) policies to restrict the use of dangerous capabilities in non-infrastructure namespaces.
- Review the identity (IAM principal) associated with pod creation to ensure RBAC is scoped appropriately for users or CI/CD pipelines.
