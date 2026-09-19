---
title: Monitoring Unauthorized Amazon EKS Access Entry Modifications
slug: 2026-09-eks-access-entry-modification
description: Detection of unauthorized Amazon EKS Access Entry modifications via AWS CloudTrail, which may be used by attackers to achieve persistent access or privilege escalation in Kubernetes clusters.
date: "2026-09-19T01:06:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - kubernetes
  - persistence
  - privilege-escalation
  - aws
vendors:
  - Amazon
products:
  - Elastic Kubernetes Service (EKS)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Attackers may create or update these entries to grant themselves persistent access or elevated privileges within a Kubernetes cluster.
    confidence_band: high
rules:
  - title: Detect Unauthorized Amazon EKS Access Entry Modifications
    description: Detects successful EKS Access Entry API operations that create, update, or modify authentication mappings, which could indicate unauthorized privilege escalation or persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1098.006
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor AWS CloudTrail logs for unexpected EKS Access Entry modifications.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search CloudTrail for any 'CreateAccessEntry' or 'AssociateAccessPolicy' events where the IAM principal is not a known service account.
      technique_id: T1098.006
      data_needed:
        - AWS CloudTrail logs
      priority: medium
      confidence: high
      disposition: hunt_now
---

Amazon EKS Access Entries allow administrators to map IAM principals to Kubernetes permissions, simplifying cluster authentication. Attackers can abuse this mechanism to gain persistent access or escalate privileges by creating, updating, or associating access policies with malicious or compromised IAM principals. Because these entries modify authentication mappings outside of standard in-cluster Kubernetes RBAC objects, they can be used to bypass existing security controls and maintain a foothold within the cluster environment. Defenders should monitor for unexpected changes to these entries that do not correlate with known infrastructure-as-code or automated deployment activities.

## Impact

Successful abuse of EKS Access Entries can allow an attacker to gain persistent, unauthorized access to a Kubernetes cluster, potentially leading to unauthorized data access, lateral movement, or service disruption. Monitoring for these changes helps identify unauthorized privilege escalation or persistence efforts before they are leveraged for further malicious activity.

## Recommendation

- Implement monitoring for the specific CloudTrail actions listed in the Sigma rule below to detect unauthorized cluster access changes.
- Review and baseline existing IAM roles utilized by deployment pipelines (e.g., terraform, eksctl) to reduce false positives in detection logic.
- Pair these alerts with Kubernetes audit log monitoring to track subsequent API activity performed by identities tied to newly created or updated access entries.
- Use AWS IAM and Service Control Policies (SCPs) to restrict access to EKS configuration APIs to authorized administrators only.
