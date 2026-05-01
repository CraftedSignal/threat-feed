---
title: AWS EC2 Stop, Start, and User Data Modification Correlation
slug: 2024-01-03-aws-ec2-user-data-modification
description: Detection of a sequence of AWS EC2 management API calls indicative of malicious modification of instance user data to execute arbitrary code upon instance restart, potentially leading to privilege escalation and persistence.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - ec2
  - user-data
  - privilege-escalation
  - persistence
  - execution
vendors:
  - Amazon
products:
  - EC2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyInstanceAttribute.html
  - https://hackingthe.cloud/aws/exploitation/local_ec2_priv_esc_through_user_data
rules:
  - title: Detect EC2 User Data Modification
    description: Detects modification of EC2 instance user data via the ModifyInstanceAttribute API call.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1578
    data_sources:
      - cloudtrail
      - aws
  - title: Detect EC2 Instance Stop Followed by Start
    description: Detects a stop and start event of an EC2 instance within a short timeframe. This is often done to trigger execution of modified user data.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.009
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS EC2 Stop, Start, and User Data Modification Correlation (Single Event)
    description: This rule detects a single CloudTrail event containing EC2 StopInstances, StartInstances, or ModifyInstanceAttribute events involving UserData.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.009
      - T1578
    data_sources:
      - cloudtrail
      - aws
rules_count: 3
---

This detection identifies a specific sequence of AWS EC2 API calls suggesting malicious intent. An adversary may update the `userData` attribute of an EC2 instance and then restart the instance to execute malicious scripts with elevated privileges (root on Linux, SYSTEM on Windows). The technique involves modifying instance attributes to inject malicious code or scripts, followed by stopping and starting the instance to trigger execution of the modified user data. This can lead to privilege escalation, persistence, or other malicious activities within the AWS environment. The detection focuses on the correlation of `StopInstances`, `StartInstances`, and `ModifyInstanceAttribute` events that reference `userData` within a 5-minute window. The rule groups these events by instance ID, username, account ID, source IP, and user agent, triggering an alert only when all three distinct API calls are observed within the same group. This aims to reduce false positives by requiring the complete sequence of actions associated with this technique.

## Attack Chain

1. An attacker gains initial access to an AWS account with sufficient permissions to manage EC2 instances (e.g., via compromised credentials or an IAM role).
2. The attacker identifies a target EC2 instance.
3. The attacker uses the `ModifyInstanceAttribute` API call to update the `userData` attribute of the target instance, injecting malicious code or scripts.
4. The attacker uses the `StopInstances` API call to stop the target EC2 instance.
5. The attacker uses the `StartInstances` API call to start the target EC2 instance.
6. Upon instance start, the modified `userData` script executes with elevated privileges, potentially installing malware, establishing persistence, or performing other malicious actions.
7. The attacker may use the compromised instance to further explore the AWS environment, escalate privileges, or exfiltrate data.

## Impact

Successful exploitation can lead to unauthorized code execution within the AWS environment. Attackers can gain elevated privileges on the compromised EC2 instance, potentially leading to full control of the instance and the ability to access sensitive data or resources within the AWS account. This can result in data breaches, service disruptions, and financial losses. The modification of user data allows for persistent malicious code execution each time the instance restarts.

## Recommendation

*   Deploy the following Sigma rules to your SIEM to detect the described attack pattern, and tune them to your environment.
*   Review CloudTrail logs for `ModifyInstanceAttribute` events with `userData` to identify potentially malicious modifications.
*   Monitor EC2 instance state transitions (stop/start) in conjunction with user data modifications.
*   Implement least privilege IAM policies to restrict access to EC2 management APIs.
*   Use AWS Secrets Manager or Parameter Store to manage secrets instead of embedding them in `userData`.
*   Investigate any alerts generated by the Sigma rules and correlate them with other security events.
