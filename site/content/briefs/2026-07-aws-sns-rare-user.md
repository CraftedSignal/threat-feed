---
title: AWS SNS Topic Message Published by Rare User
slug: 2026-07-aws-sns-rare-user
description: This high-severity threat involves adversaries publishing messages to an AWS SNS topic using compromised credentials, identified when a user or role performs this action for the first time, potentially facilitating phishing campaigns, data exfiltration, or lateral movement within an AWS environment.
date: "2026-07-15T14:13:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - lateral-movement
  - exfiltration
  - impact
  - command-and-control
vendors:
  - Amazon
products:
  - AWS SNS
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1534
    technique_name: Internal Spearphishing
    evidence: Adversaries may publish messages to SNS topics for phishing campaigns, data exfiltration, or lateral movement within the AWS environment.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Adversaries may publish messages to SNS topics for phishing campaigns, data exfiltration, or lateral movement within the AWS environment.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: Adversaries may publish messages to SNS topics for phishing campaigns, data exfiltration, or lateral movement within the AWS environment.
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: SNS topics are used to send notifications and messages to subscribed endpoints... making them a valuable target for adversaries to distribute malicious content.
    confidence_band: med
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_Publish.html
  - https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/
  - https://permiso.io/blog/s/smishing-attack-on-aws-sms-new-phone-who-dis/
  - https://www.sentinelone.com/labs/sns-sender-active-campaigns-unleash-messaging-spam-through-the-cloud/
rules:
  - title: AWS SNS Topic Message Publish Detected
    description: Detects the publication of messages to an AWS SNS topic. This rule is typically used in conjunction with behavioral analytics to identify publications by rare or newly observed users/roles, which can indicate lateral movement, data exfiltration, or phishing attempts.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - exfiltration
      - impact
      - lateral_movement
    techniques:
      - T1102
      - T1496.004
      - T1534
      - T1567
    data_sources:
      - cloud
      - aws
      - aws.cloudtrail
rules_count: 1
---

Adversaries are leveraging compromised AWS credentials to publish messages to Amazon Simple Notification Service (SNS) topics, a tactic detected when the publishing user or role is observed performing this action for the first time. This behavior, often indicative of an attack, can be exploited for various malicious purposes, including launching phishing campaigns, exfiltrating sensitive data, or achieving lateral movement within the AWS cloud environment. SNS topics are critical infrastructure for sending notifications and messages to subscribed endpoints such as applications, mobile devices, or email addresses, making them a valuable target for distributing malicious content or extracting information. The detection relies on AWS CloudTrail logs, specifically monitoring `sns.amazonaws.com:Publish` events with `outcome:success`, focusing on activities from previously unobserved or rarely active entities to identify anomalous and potentially malicious usage.

## Attack Chain

1. **Initial Access**: An adversary successfully compromises an AWS IAM user account or role, an EC2 instance, or gains access through a vulnerable application, acquiring valid AWS credentials.
2. **Privilege Escalation/Lateral Movement**: The adversary uses the initial compromise to identify and leverage permissions that allow interaction with AWS SNS, or moves laterally to an environment where such permissions are already available.
3. **SNS Topic Message Publication**: Using the compromised credentials, the adversary publishes a message to an existing SNS topic. This action often appears as a rare or novel behavior for the specific user or role performing it, triggering anomaly detection.
4. **Message Delivery**: The malicious message is then delivered to all configured subscribed endpoints of the SNS topic, which can include email addresses, SMS recipients, Amazon SQS queues, or AWS Lambda functions.
5. **Malicious Activity Execution**: Depending on the attacker's objective, the published message might contain phishing links targeting internal users, exfiltrated sensitive data embedded within the message, or commands intended for further lateral movement or resource hijacking.
6. **Impact**: The successful delivery of the malicious message results in various impacts such as successful phishing campaigns, unauthorized data exfiltration, further compromise of systems, or disruption of business operations.

## Impact

The successful exploitation of SNS topic publishing can lead to severe consequences for an organization. Adversaries can initiate targeted phishing campaigns against internal employees or external customers by distributing malicious links or content via SMS or email subscribers, leading to further credential theft or malware infection. Sensitive data exfiltration can occur if an attacker publishes proprietary information to an SNS topic with external subscriptions. Furthermore, the ability to control message distribution can facilitate lateral movement within the cloud environment by triggering malicious Lambda functions or sending instructions to other compromised systems, potentially leading to widespread system compromise, resource hijacking, or service disruption.

## Recommendation

* Deploy the Sigma rule "AWS SNS Topic Message Publish Detected" to your SIEM and configure it to identify anomalous behavior by users or roles rarely observed publishing SNS messages.
* Ensure that AWS CloudTrail data events are enabled for SNS topic logging to capture the `Publish` action as specified in the rule's `setup` section.
* Investigate `aws.cloudtrail.user_identity.arn`, `source.ip`, and `user_agent.original` fields from the `aws.cloudtrail` logs for any SNS `Publish` events that are flagged.
* If unauthorized activity is confirmed, disable the `aws.cloudtrail.user_identity.access_key_id` or IAM role associated with the malicious user, as suggested in the "Response and Remediation" section.
* Audit IAM policies associated with users and SNS topics to ensure appropriate permissions are in place, as recommended in the "Review Policies and Subscriptions" section.
