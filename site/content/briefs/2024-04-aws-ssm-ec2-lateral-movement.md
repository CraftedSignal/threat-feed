---
title: AWS SSM Session Started to EC2 Instance for Lateral Movement
slug: 2024-04-aws-ssm-ec2-lateral-movement
description: An AWS user or role establishing a session via SSM to an EC2 instance may indicate lateral movement, and this rule detects the first occurrence of such an event.
date: "2024-04-17T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - lateral-movement
  - ssm
vendors:
  - AWS
products:
  - AWS Systems Manager
  - AWS EC2
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_StartSession.html
  - https://hackingthe.cloud/aws/post_exploitation/intercept_ssm_communications/
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ssm-privesc
  - https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques
rules:
  - title: AWS SSM Session Started to EC2 Instance
    description: Detects the first occurrence of an AWS user or role establishing a session via SSM to an EC2 instance.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.007
    data_sources:
      - cloudtrail
      - aws
  - title: AWS SSM Session Started from Unusual Source IP
    description: Detects AWS SSM sessions started from unusual or suspicious IP addresses.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - lateral_movement
    techniques:
      - T1021.007
      - T1071.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the initial establishment of an AWS Session Manager (SSM) session to an EC2 instance by a user or role. While SSM is a legitimate tool for managing EC2 instances, adversaries can abuse it for lateral movement and command execution. This activity is detected using AWS CloudTrail logs, specifically events from the `ssm.amazonaws.com` provider with the `StartSession` action. The rule aims to flag suspicious SSM session initiations that might deviate from established administrative practices. It's important to differentiate between legitimate administrative tasks and potentially malicious actions stemming from compromised credentials or insider threats. This activity can be used to gain access to the instance and perform actions such as privilege escalation.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or an exposed access key.
2. The attacker leverages the AWS CLI or SDK to authenticate to the AWS environment.
3. The attacker identifies a target EC2 instance within the AWS environment.
4. The attacker uses the SSM `StartSession` API call to establish a remote session to the identified EC2 instance. The request parameters include the instance ID.
5. The `StartSession` action is logged in AWS CloudTrail with `event.provider` as `ssm.amazonaws.com` and `event.action` as `StartSession`.
6. Once the session is established, the attacker can execute commands on the EC2 instance.
7. The attacker performs reconnaissance to identify sensitive data, misconfigurations, or further lateral movement opportunities.
8. The attacker escalates privileges or moves laterally to other resources within the AWS environment to achieve their objectives (e.g., data exfiltration).

## Impact

Successful exploitation could lead to unauthorized access to sensitive data, compromised systems, and broader lateral movement within the AWS environment. The impact ranges from data breaches and service disruption to complete infrastructure takeover, depending on the privileges associated with the compromised account and the scope of the attacker's lateral movement. The lack of immediate detection can allow attackers to establish persistent access and move undetected for extended periods.

## Recommendation

*   Deploy the Sigma rule "AWS SSM Session Started to EC2 Instance" to your SIEM and tune for your environment to detect initial session establishment (rules).
*   Investigate any identified SSM session initiations, paying close attention to the user identity (`aws.cloudtrail.user_identity.arn`) and source IP address (`source.ip`).
*   Review the AWS Systems Manager documentation and AWS SSM privilege escalation techniques to understand security best practices and potential attack vectors (references).
*   Monitor AWS CloudTrail logs for `StartSession` events from the `ssm.amazonaws.com` provider to detect suspicious session activity (logsource).
*   Ensure that IAM policies around SSM session initiation are strict and adhere to the principle of least privilege to limit the blast radius of compromised credentials (references).
