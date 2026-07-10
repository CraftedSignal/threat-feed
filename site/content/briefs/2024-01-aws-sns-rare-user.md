---
title: AWS SNS Topic Message Publish by Rare User
slug: 2024-01-aws-sns-rare-user
description: This rule identifies when an SNS topic message is published by a rare user in AWS, which may indicate lateral movement, data exfiltration, or phishing campaigns, potentially leading to resource hijacking and impact on cloud services.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - sns
  - lateral-movement
  - exfiltration
  - impact
vendors:
  - Amazon
products:
  - Amazon Simple Notification Service
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1534
    technique_name: Internal Spearphishing
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_Publish.html
  - https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/
  - https://permiso.io/blog/s/smishing-attack-on-aws-sms-new-phone-who-dis/
  - https://www.sentinelone.com/labs/sns-sender-active-campaigns-unleash-messaging-spam-through-the-cloud/
rules:
  - title: AWS SNS Topic Message Publish by Rare User (Sigma)
    description: Detects when an SNS topic message is published by a rare user in AWS CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
      - impact
      - lateral_movement
    techniques:
      - T1496
      - T1534
      - T1567
    data_sources:
      - cloudtrail
      - aws
      - sns
  - title: AWS SNS Topic Abuse - Unusual Source IP
    description: Detects SNS publish events originating from unusual source IP addresses.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - lateral_movement
    techniques:
      - T1102
      - T1534
    data_sources:
      - cloudtrail
      - aws
      - sns
rules_count: 2
---

This detection rule identifies when a user or role publishes a message to an Amazon Simple Notification Service (SNS) topic for the first time. Attackers may abuse SNS topics for various malicious purposes, including internal spearphishing, data exfiltration, or lateral movement within the AWS environment. SNS topics are used to send notifications and messages to subscribed endpoints such as applications, mobile devices, or email addresses. A successful attack could lead to sensitive data being exposed or malicious content being distributed to a wide range of recipients. This rule leverages a "new terms" approach, focusing on identifying previously unseen behavior to surface potentially suspicious activity. It helps security teams detect unusual SNS activity and investigate potential security breaches in AWS environments.

## Attack Chain

1.  An attacker gains initial access to an AWS environment, potentially through compromised credentials or exploiting a misconfigured IAM role.
2.  The attacker discovers accessible SNS topics within the AWS environment using AWS CLI or SDKs.
3.  The attacker identifies an SNS topic with a broad subscription base, such as one connected to an internal communications channel.
4.  The attacker publishes a malicious message to the SNS topic using the AWS CLI, SDK, or AWS Management Console, utilizing a rare or new user account.
5.  The SNS service delivers the message to all subscribed endpoints, including applications, mobile devices, or email addresses.
6.  Recipients of the malicious message may be tricked into clicking on a phishing link or downloading malicious content, leading to further compromise of their systems.
7.  The attacker may leverage the compromised systems for lateral movement, data exfiltration, or other malicious activities.
8.  The attacker achieves impact by spreading malware, stealing sensitive information, or disrupting business operations through the compromised systems and data.

## Impact

A successful attack exploiting SNS topics can lead to several negative consequences. Internal spearphishing attacks could compromise employees and sensitive data. Data exfiltration through SNS messages may lead to regulatory violations and reputational damage. Resource hijacking could allow attackers to leverage AWS resources for malicious purposes, increasing costs and potentially disrupting services. Organizations in any sector that rely on AWS for their infrastructure are vulnerable, and the number of potential victims depends on the scope and reach of the SNS topic subscriptions.

## Recommendation

*   Enable AWS CloudTrail logging for SNS data events to ensure the necessary logs are captured (reference: setup section).
*   Deploy the provided Sigma rule to your SIEM to detect rare users publishing SNS messages (reference: rules section). Tune the `history_window_start` parameter in the rule to match your environment's baseline.
*   Investigate any alerts generated by the Sigma rule, focusing on the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.resources.arn` to identify the actor and SNS topic involved (reference: rule.investigation_fields).
*   Review IAM policies associated with users and roles publishing to SNS topics to ensure appropriate permissions are enforced and minimize potential misuse (reference: T1534, T1496).
*   Monitor for unusual API calls related to SNS, such as `AssumeRole` or `CreateAccessKey`, associated with the rare user (reference: T1102).
