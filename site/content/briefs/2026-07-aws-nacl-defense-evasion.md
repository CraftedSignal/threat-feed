---
title: Detection of Unauthorized AWS NACL Modification by New Identities
slug: 2026-07-aws-nacl-defense-evasion
description: Adversaries may modify AWS Network Access Control Lists (NACLs) to allow all traffic, effectively disabling network-layer defenses to facilitate lateral movement or data exfiltration, a behavior this detection identifies when performed by previously unseen identities.
date: "2026-07-30T13:32:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud
  - defense-evasion
vendors:
  - Amazon
products:
  - AWS EC2
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The rule detects attempts to create or replace AWS Network Access Control List (NACL) entries using protocol -1, which would disable network-layer controls.
    confidence_band: high
---

This threat detection focuses on the abuse of AWS NACLs to weaken perimeter security. An attacker who has gained unauthorized access to an AWS environment may attempt to neutralize network-layer controls by creating or replacing NACL entries with a protocol value of -1, which permits all traffic across all ports. This action creates a significant security gap, often used to ensure unrestricted communication for C2 beacons, tools, or exfiltration channels. 

The detection logic specifically flags when these modifications are performed by an identity that has not been observed in the environment within the previous 7-day window. By excluding known Infrastructure-as-Code (IaC) tooling, the rule reduces noise from authorized automation, highlighting potentially malicious credential usage or unauthorized manual changes by an attacker or a compromised principal. This monitoring is critical for identifying defense-in-depth erosion in cloud environments.

## Attack Chain

1. Attacker gains initial access to AWS credentials (e.g., via stolen access keys or compromised IAM roles).
2. Attacker performs reconnaissance to identify network architecture, including VPCs, subnets, and associated NACLs.
3. Attacker evaluates existing NACL rules to determine which subnets contain sensitive assets or lack comprehensive security group coverage.
4. Attacker uses the `CreateNetworkAclEntry` or `ReplaceNetworkAclEntry` API calls via the AWS CLI or SDK.
5. The attacker specifies `Protocol: -1` and `RuleAction: allow` to permit all traffic (0-65535) into or out of the target subnets.
6. Attacker confirms the successful application of the rule via subsequent API calls or by attempting unauthorized connectivity.
7. Attacker utilizes the newly open network path to conduct lateral movement or exfiltrate data from previously restricted instances.

## Impact

Successful exploitation of this technique neutralizes a primary defense-in-depth layer within an AWS VPC. By opening all ports to all protocols, an adversary can bypass existing port-based restrictions, potentially exposing internal workloads directly to the internet or facilitating rapid unauthorized movement across segmented subnets, leading to increased risk of data theft or system compromise.

## Recommendation

- Implement the provided detection logic to alert on `CreateNetworkAclEntry` or `ReplaceNetworkAclEntry` events where the protocol is set to -1, filtered by new-identity tracking.
- Review all existing NACL configurations to ensure that permissive rules are only utilized where strictly required for stateless passthrough, and ensure security groups are the primary mechanism for access control.
- Establish a baseline of authorized IaC user agents to ensure the exclusion filter effectively suppresses legitimate infrastructure deployments.
- Investigate any triggered alerts by reviewing associated VPC flow logs to identify abnormal traffic patterns on the subnets modified by the suspect identity.
