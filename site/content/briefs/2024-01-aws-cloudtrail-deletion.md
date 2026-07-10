---
title: AWS CloudTrail Log Deletion for Defense Evasion
slug: 2024-01-aws-cloudtrail-deletion
description: An adversary deletes AWS CloudTrail logs to evade detection and operate stealthily within a compromised AWS environment, removing audit trails of their malicious activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - defense-evasion
  - cloud
vendors:
  - AWS
products:
  - CloudTrail
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: AWS CloudTrail Trail Deletion
    description: Detects deletion of AWS CloudTrail trails by non-console users, which can indicate defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudTrail Trail Deletion - API
    description: Detects deletion of AWS CloudTrail trails via direct API calls, potentially indicating programmatic defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on the detection of malicious actors deleting AWS CloudTrail logs within a compromised AWS environment. AWS CloudTrail is a service that enables governance, compliance, operational auditing, and risk auditing of an AWS account. Attackers may attempt to delete these logs to remove evidence of their activities, making it more difficult for defenders to investigate and respond to security incidents. This is a defense evasion technique that can significantly hinder incident response efforts. The deletion is detected by monitoring `DeleteTrail` events within CloudTrail logs, excluding those originating from the AWS console. Successful deletion of CloudTrail logs allows attackers to cover their tracks, potentially leading to prolonged unauthorized access and further exploitation.

## Attack Chain

1.  The attacker gains initial access to an AWS account through compromised credentials or by exploiting a vulnerability in an AWS service.
2.  The attacker enumerates existing CloudTrail trails to identify the target log storage.
3.  The attacker escalates privileges within the AWS environment to gain sufficient permissions to delete CloudTrail trails. This may involve exploiting IAM misconfigurations or vulnerabilities.
4.  The attacker uses the AWS CLI or API to execute the `DeleteTrail` command, specifying the name of the CloudTrail trail to be deleted.
5.  CloudTrail logs the `DeleteTrail` event, including the user identity, source IP address, and timestamp of the deletion attempt.
6.  If the deletion is successful, the targeted CloudTrail log is permanently removed, eliminating valuable audit data.
7.  The attacker continues with their malicious activities, now with reduced risk of detection due to the absence of CloudTrail logs.

## Impact

The successful deletion of CloudTrail logs can have severe consequences. It can hinder incident response efforts, making it difficult to identify the scope and nature of a security breach. The number of affected organizations depends on the scope of the initial compromise. The sectors most at risk are those that rely heavily on AWS for their infrastructure, including e-commerce, finance, and healthcare. Successful deletion allows attackers to operate undetected, potentially leading to data theft, system compromise, and financial loss.

## Recommendation

*   Deploy the Sigma rule `AWS CloudTrail Trail Deletion` to detect `DeleteTrail` events and alert on suspicious activity (rule provided below).
*   Enable and monitor AWS CloudTrail logs for `DeleteTrail` events and ensure proper log retention policies are in place (data_source: `AWS CloudTrail DeleteTrail`).
*   Investigate any `DeleteTrail` events that do not originate from authorized administrative accounts or processes (`eventName = DeleteTrail`, `userAgent !=console.amazonaws.com`).
*   Review and enforce strict IAM policies to restrict the ability to delete CloudTrail trails to a limited number of highly privileged accounts.
*   Implement multi-factor authentication (MFA) for all AWS accounts, especially those with permissions to modify or delete CloudTrail configurations.
