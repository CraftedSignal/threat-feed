---
title: AWS EKS Control Plane Logging Disabled
slug: 2026-07-aws-eks-control-plane-logging-disabled
description: Elastic identified a defense evasion technique where an attacker, having gained unauthorized access, issues an UpdateClusterConfig request to disable Amazon EKS control plane logging, significantly reducing visibility into subsequent malicious cluster activity.
date: "2026-07-15T13:58:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - kubernetes
  - aws
  - defense-evasion
vendors:
  - Amazon
products:
  - Amazon EKS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects successful Amazon EKS UpdateClusterConfig requests that disable control plane logging. Disabling EKS API server and control plane logs can reduce visibility into cluster activity and may indicate defense evasion.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
  - https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdateClusterConfig.html
rules:
  - title: AWS EKS Control Plane Logging Disabled
    description: Detects successful Amazon EKS UpdateClusterConfig requests that disable control plane logging, indicating defense evasion following compromised AWS credentials or unauthorized administrative access.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.008
    data_sources:
      - cloud
      - aws
      - cloudtrail
rules_count: 1
---

Attackers with compromised AWS credentials or unauthorized administrative access are exploiting the `UpdateClusterConfig` API to disable Amazon EKS control plane logging, a critical defense evasion tactic. This action, detected by Elastic, dramatically reduces an organization's ability to monitor and detect malicious activity within their Kubernetes clusters running on AWS EKS. Disabling these logs severely hampers incident response efforts by obscuring attacker actions, making it challenging to identify the scope of a compromise or the techniques used. This tactic is often employed post-initial access to establish persistence and escalate privileges undetected. Organizations need robust detection mechanisms for such configuration changes to mitigate the risk of hidden lateral movement and data exfiltration within their cloud environments.

## Attack Chain

1. **Initial Access**: An attacker gains initial access to an AWS environment, often through compromised credentials, insecure access keys, or vulnerable web applications.
2. **Credential Acquisition**: The attacker acquires valid AWS credentials (e.g., IAM user credentials, temporary session credentials from an assumed role, or access keys from an EC2 instance).
3. **Authentication**: The attacker authenticates to the AWS API using the compromised credentials, potentially via the AWS CLI or SDK, or through an `sts:AssumeRole` operation.
4. **API Call - `eks:UpdateClusterConfig`**: The attacker makes an AWS API call to `eks.amazonaws.com` targeting the `UpdateClusterConfig` action for a specific EKS cluster.
5. **Logging Modification**: Within the `UpdateClusterConfig` request, the attacker modifies the cluster's logging configuration, specifically setting one or more control plane log types to `enabled=false`.
6. **Confirmation and Execution**: The AWS EKS service successfully processes the request, disabling the specified control plane logs for the target cluster.
7. **Defense Evasion**: With logging disabled, the attacker proceeds with further malicious activities within the EKS cluster (e.g., deploying malicious containers, exfiltrating data, maintaining persistence) with significantly reduced forensic visibility.

## Impact

Successful execution of this defense evasion technique leads to a severe degradation of security visibility within affected Amazon EKS clusters. Organizations lose critical audit trails for Kubernetes API server requests, scheduler activity, controller manager actions, and other vital control plane operations. This blind spot allows attackers to move laterally, exfiltrate data, or deploy persistent backdoors without leaving readily available evidence, significantly increasing the time to detect and respond to security incidents. The primary consequence is the ability for attackers to operate undetected, leading to potential data breaches, resource abuse, and compromise of critical applications and services hosted on EKS.

## Recommendation

* Deploy the Sigma rule "AWS EKS Control Plane Logging Disabled" to your SIEM and tune for your environment to detect unauthorized changes.
* Monitor AWS CloudTrail logs for `event.action:"UpdateClusterConfig"` and `event.provider:"eks.amazonaws.com"` to identify configuration changes.
* Restrict IAM permissions allowing `eks:UpdateClusterConfig` to only authorized roles and automate the process where possible, ensuring least privilege.
* Investigate all alerts generated by the "AWS EKS Control Plane Logging Disabled" rule, focusing on the `user.name`, `aws.cloudtrail.user_identity.arn`, `source.ip`, and `user_agent.original` fields.
* Correlate `UpdateClusterConfig` events with other EKS and IAM activity (e.g., access entry changes, IAM policy attachments, STS assume events) from the same principal to detect broader compromise.
