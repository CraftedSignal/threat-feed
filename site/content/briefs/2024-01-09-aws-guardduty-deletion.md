---
title: AWS GuardDuty Detector Deletion
slug: 2024-01-09-aws-guardduty-deletion
description: Detection of AWS GuardDuty detector deletion via the DeleteDetector API, potentially indicating defense evasion by an attacker disabling threat monitoring and removing findings.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - guardduty
  - defense-evasion
vendors:
  - AWS
products:
  - GuardDuty
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html
  - https://github.com/aws-samples/aws-incident-response-playbooks/blob/c151b0dc091755fffd4d662a8f29e2f6794da52c/playbooks/
  - https://github.com/aws-samples/aws-customer-playbook-framework/tree/a8c7b313636b406a375952ac00b2d68e89a991f2/docs
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS GuardDuty Detector Deletion
    description: Detects the deletion of an AWS GuardDuty detector, which could indicate an attacker attempting to disable threat monitoring and evade detection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS GuardDuty Configuration Changes Prior to Deletion
    description: Detects suspicious GuardDuty configuration changes (StopMonitoringMembers, DisassociateMembers, or DeleteMembers) that may precede a detector deletion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The AWS GuardDuty Detector Deletion rule identifies successful `DeleteDetector` API calls, which could signal an attacker attempting to impair defenses and evade detection within an AWS environment. GuardDuty is a continuous threat detection service that monitors CloudTrail, DNS logs, and VPC Flow Logs to identify malicious activity. Deleting the detector stops all monitoring and permanently removes historical findings for the affected AWS account, thus creating a blind spot for security teams. This activity is often indicative of a post-compromise scenario where the attacker seeks to remove traces of their presence and hinder incident response efforts. This rule is relevant for organizations that rely on GuardDuty for threat detection and incident response in their AWS environments. The original rule was created on 2020/05/28 and updated on 2026/04/10.

## Attack Chain

1.  Initial access is gained to an AWS account through compromised credentials or a vulnerability in an exposed service.
2.  The attacker escalates privileges within the AWS environment to gain sufficient permissions to manage GuardDuty.
3.  The attacker uses the AWS CLI or API to execute the `DeleteDetector` API call, targeting the GuardDuty detector in a specific region.
4.  The `DeleteDetector` API call succeeds, disabling GuardDuty monitoring and deleting existing findings.
5.  The attacker performs malicious activities within the AWS environment, such as lateral movement, data exfiltration, or resource tampering, without detection by GuardDuty.
6.  The attacker may attempt to delete or modify CloudTrail logs to further obscure their activity and hinder forensic analysis.
7.  The attacker completes their objectives, such as deploying ransomware or stealing sensitive data.
8.  The attacker attempts to remove or obfuscate any remaining logs, making it difficult to trace back to the initial intrusion.

## Impact

Successful deletion of a GuardDuty detector can severely compromise an organization's security posture in AWS. It allows attackers to operate undetected, leading to potential data breaches, financial loss, and reputational damage. The loss of GuardDuty's continuous monitoring can extend the dwell time of attackers within the environment, increasing the potential for significant damage. Organizations across all sectors that rely on AWS are at risk. The impact can range from data exfiltration and resource hijacking to full-scale ransomware deployment, depending on the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule `AWS GuardDuty Detector Deletion` to your SIEM to detect unauthorized deletions of GuardDuty detectors.
*   Review `aws.cloudtrail.user_identity.arn` from CloudTrail logs to identify the actor initiating the `DeleteDetector` API call.
*   Implement AWS Config rules or Security Hub controls to alert on changes to GuardDuty detectors or configuration states as described in the overview.
*   Restrict `guardduty:DeleteDetector` permissions to a limited administrative role using IAM policies.
*   Enable AWS CloudTrail logging and monitor for `DeleteDetector` events, ensuring logs are stored securely and retained for a sufficient period.
*   Investigate any `DeleteDetector` API calls that do not correspond to legitimate account decommissioning, region cleanup, or migration activity as described in the "False positive analysis" section.
