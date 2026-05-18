---
title: AWS EKS Control Plane Logging Disabled
slug: 2026-05-aws-eks-control-plane-logging-disabled
description: This rule detects successful Amazon EKS UpdateClusterConfig requests that disable control plane logging, potentially indicating defense evasion via compromised AWS credentials or unauthorized administrative access that reduces visibility into cluster activity.
date: "2026-05-18T13:13:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - kubernetes
  - aws
  - defense_evasion
vendors:
  - Amazon
products:
  - EKS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
  - https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdateClusterConfig.html
rules:
  - title: Detect AWS EKS Control Plane Logging Disabled
    description: Detects successful Amazon EKS UpdateClusterConfig requests that disable control plane logging.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: Detect EKS UpdateClusterConfig Request
    description: Detects any Amazon EKS UpdateClusterConfig requests. This can be used to monitor changes to cluster configuration.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies instances where Amazon Elastic Kubernetes Service (EKS) control plane logging is disabled via the `UpdateClusterConfig` API. Attackers may disable these logs to evade detection and reduce visibility into their activities within the Kubernetes cluster. The disabling of EKS API server and control plane logs is typically rare and should align with approved maintenance or cost optimization workflows. The rule focuses on successful attempts to disable logging, indicating a potential security compromise. This is important for defenders as it can highlight a significant gap in security monitoring within their EKS environments.

## Attack Chain

1.  Initial access is gained through compromised AWS credentials or unauthorized administrative access.
2.  The attacker authenticates to the AWS environment using the compromised credentials or leverages existing administrative access.
3.  The attacker identifies the target EKS cluster for which they want to disable logging.
4.  The attacker calls the `UpdateClusterConfig` API endpoint to modify the logging configuration.
5.  Within the `request_parameters` of the API call, the `logging` setting is modified to `enabled=false`.
6.  The EKS control plane successfully processes the request and disables the logging configuration.
7.  The logs stop being generated from the EKS control plane, reducing visibility into cluster activity.
8.  The attacker proceeds with further malicious activities within the cluster, now with reduced risk of detection via control plane logs.

## Impact

Disabling EKS control plane logging can severely impact an organization's ability to detect and respond to threats within their Kubernetes environment. The number of affected clusters depends on the scope of the attacker's access and objectives. This activity targets any AWS EKS user. Successful evasion allows threat actors to operate with impunity, potentially leading to data breaches, service disruptions, or other malicious outcomes.

## Recommendation

*   Deploy the Sigma rule "Detect AWS EKS Control Plane Logging Disabled" to your SIEM and tune for your environment to detect this specific behavior.
*   Enable AWS CloudTrail logging and ensure proper configuration of the `logs-aws.cloudtrail-*` index to provide the necessary log data for the Sigma rule.
*   Review IAM permissions to restrict `eks:UpdateClusterConfig` to only authorized personnel and services, as described in the rule overview.
*   Investigate any detected instances of disabled EKS control plane logging by validating the caller identity and change records, and baseline expected automation roles, according to the false positives section.
