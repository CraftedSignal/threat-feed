---
title: Detection of AWS Route 53 Resolver Query Log Deletion
slug: 2026-09-route53-log-deletion
description: Adversaries may delete Amazon Route 53 Resolver Query Log configurations to evade detection by disabling DNS query and response logging for VPC-based resources.
date: "2026-09-18T19:27:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - defense-evasion
  - log-auditing
vendors:
  - Amazon
products:
  - Route 53
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries may delete these configurations to evade detection, suppress forensic evidence, or degrade security monitoring capabilities.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_DeleteResolverQueryLogConfig.html
rules:
  - title: Detect AWS Route 53 Resolver Query Log Deletion
    description: Detects successful execution of DeleteResolverQueryLogConfig which disables DNS logging for VPCs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
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
    - action: Deploy Sigma detection rule to monitor CloudTrail for DeleteResolverQueryLogConfig.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 453183fa-f903-11ee-8e88-f661ea17fbce
  hunt_leads:
    - lead: Audit CloudTrail history for DeleteResolverQueryLogConfig occurrences in the last 6 months.
      technique_id: T1562.008
      data_needed:
        - CloudTrail logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation identifies this as an adversarial technique to suppress logging.
  mitigation_plan:
    - priority: immediate
      action: Restrict IAM permissions for route53resolver:DeleteResolverQueryLogConfig to authorized personnel only.
      owner: IT Operations
      addresses: T1562.008
      evidence: Best practice to prevent unauthorized defense impairment.
---

Adversaries targeting AWS environments may attempt to disable security monitoring by deleting Amazon Route 53 Resolver Query Log configurations. These logs provide critical visibility into DNS activity across VPCs, including queries initiated by EC2 instances, containerized workloads, and Lambda functions. By successfully invoking the `DeleteResolverQueryLogConfig` API call, an attacker immediately halts DNS logging, effectively creating a blind spot that hides evidence of command-and-control (C2) communication, lateral movement, and data exfiltration. This tactic is classified as a method of impairing defenses within cloud environments, forcing defenders to rely on fragmented telemetry when investigating unauthorized resource access or configuration tampering.

## Attack Chain

1. Attacker gains initial access to an AWS account via compromised IAM credentials or a service role.
2. Attacker performs reconnaissance to identify enabled security logging configurations, specifically checking Route 53 Resolver Query Log settings.
3. Attacker evaluates existing IAM permissions to determine if the `route53resolver:DeleteResolverQueryLogConfig` action is authorized.
4. Attacker executes the `DeleteResolverQueryLogConfig` API call through the AWS CLI, SDK, or Console.
5. AWS CloudTrail logs the successful deletion event, while the Resolver service stops logging DNS traffic for the associated VPCs.
6. Attacker proceeds with malicious activity (e.g., C2 beaconing or data exfiltration) under the cover of the logging gap.
7. Defender loses visibility into DNS-based C2 indicators, delaying incident detection and response.

## Impact

The deletion of query log configurations results in the immediate loss of visibility into DNS activity across one or more VPCs. This impairment hinders the ability to detect malicious domains or suspicious DNS query patterns, which are often the primary indicators of C2 and exfiltration in cloud-native attacks. If left undetected, this allows attackers to operate within the environment for extended periods without leaving logs for forensic analysis.

## Recommendation

Prioritize the monitoring of logging-related API calls in your cloud environment to detect unauthorized tampering.
- Deploy the provided Sigma rule to alert on `DeleteResolverQueryLogConfig` events in your SIEM or logging platform.
- Audit existing IAM policies to ensure the `route53resolver:DeleteResolverQueryLogConfig` permission is granted only to highly privileged, authorized administrative roles.
- Implement AWS Service Control Policies (SCPs) or IAM boundary conditions to restrict the deletion of logging configurations to specific, trusted principal ARNs or network origins.
- Use AWS Config or Security Hub to monitor for non-compliance regarding the existence of active Resolver Query Log configurations on critical VPCs.
