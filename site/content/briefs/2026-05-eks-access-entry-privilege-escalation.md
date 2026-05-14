---
title: AWS EKS Access Entry Granted Cluster Admin Policy
slug: 2026-05-eks-access-entry-privilege-escalation
description: Detects when the AmazonEKSClusterAdminPolicy or AmazonEKSAdminPolicy is associated with a principal via the EKS Access Entries API, effectively granting full cluster-admin access and enabling potential privilege escalation and persistence.
date: "2026-05-14T15:47:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - kubernetes
  - aws
  - privilege-escalation
  - persistence
vendors:
  - AWS
products:
  - EKS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html
  - https://docs.aws.amazon.com/eks/latest/APIReference/API_AssociateAccessPolicy.html
rules:
  - title: AWS EKS Access Entry Granted Cluster Admin Policy
    description: Detects when the AmazonEKSClusterAdminPolicy or AmazonEKSAdminPolicy is associated with a principal via the EKS Access Entries API, granting cluster-admin privileges.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
      - T1098.006
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EKS AssociateAccessPolicy API call by unusual User Agent
    description: Detects AssociateAccessPolicy API calls for EKS by unusual User Agents, which may indicate attacker activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
      - T1098.006
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The rule detects the association of highly privileged policies (AmazonEKSClusterAdminPolicy or AmazonEKSAdminPolicy) with a principal through the Amazon EKS Access Entries API. This grants the associated IAM user or role full cluster-admin equivalent access. Unlike the legacy aws-auth ConfigMap, which is visible only in Kubernetes audit logs, modifications to Access Entries are recorded in CloudTrail, providing an additional detection surface. An attacker with sufficient IAM permissions to manage EKS access entries could use this API to establish a backdoor for persistence, mapping attacker-controlled IAM identities to cluster-admin privileges without altering Kubernetes resources directly. This activity is logged in AWS CloudTrail, enabling detection and response.

## Attack Chain

1.  Attacker gains initial access to an AWS account with IAM permissions to manage EKS Access Entries.
2.  Attacker enumerates available EKS clusters within the AWS account.
3.  Attacker identifies a target EKS cluster for privilege escalation.
4.  Attacker uses the `AssociateAccessPolicy` API call to associate either `AmazonEKSClusterAdminPolicy` or `AmazonEKSAdminPolicy` with a chosen IAM principal (user or role).
5.  The `AssociateAccessPolicy` request parameters include the target cluster name, access entry ARN, and policy ARN.
6.  The EKS service grants the IAM principal cluster-admin privileges within the targeted EKS cluster.
7.  Attacker uses the newly acquired cluster-admin privileges to perform unauthorized actions within the EKS cluster.
8.  Attacker maintains persistent access to the EKS cluster through the backdoored IAM principal, even if other access controls are modified.

## Impact

Successful exploitation allows attackers to gain full control over the EKS cluster. This could lead to unauthorized access to sensitive data, deployment of malicious applications, or disruption of critical services running on the cluster. The impact is significant, given that the EKS cluster likely hosts containerized applications and workloads. This attack vector could be used for long-term persistence and lateral movement within the AWS environment.

## Recommendation

*   Deploy the Sigma rule "AWS EKS Access Entry Granted Cluster Admin Policy" to your SIEM and tune for your environment to detect malicious associations of admin policies via the EKS Access Entries API.
*   Audit IAM permissions to ensure only authorized personnel can manage EKS Access Entries, specifically the `eks:AssociateAccessPolicy` action.
*   Monitor AWS CloudTrail logs for unexpected `AssociateAccessPolicy` events targeting `AmazonEKSClusterAdminPolicy` or `AmazonEKSAdminPolicy`.
*   Regularly review access entries and IAM principals associated with EKS clusters, validating the legitimacy of their permissions.
*   Implement multi-factor authentication (MFA) for all IAM users with permissions to manage EKS resources.
