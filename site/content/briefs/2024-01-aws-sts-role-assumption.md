---
title: AWS STS Role Assumption by Service for Privilege Escalation
slug: 2024-01-aws-sts-role-assumption
description: Detection of AWS services assuming roles within AWS Security Token Service (STS) to gain temporary credentials and potentially escalate privileges or move laterally within the AWS environment.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - sts
  - privilege-escalation
  - lateral-movement
vendors:
  - AWS
products:
  - AWS Security Token Service (STS)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
  - https://attack.mitre.org/techniques/T1548/
  - https://attack.mitre.org/techniques/T1548/005/
  - https://attack.mitre.org/techniques/T1550/
  - https://attack.mitre.org/techniques/T1550/001/
rules:
  - title: AWS Service Assuming Privileged Role
    description: Detects when an AWS service assumes a role, potentially indicating privilege escalation or lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
      - privilege_escalation
    techniques:
      - T1548.005
      - T1550.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS STS AssumeRole with Uncommon User Agent
    description: Detects AssumeRole calls made with unusual user agents, which can indicate malicious tools or activity.
    platform: sigma
    severity: low
    tactics:
      - lateral_movement
      - privilege_escalation
    techniques:
      - T1548.005
      - T1550.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on the abuse of AWS Security Token Service (STS) AssumeRole functionality by AWS services, as highlighted by an Elastic detection rule. The rule identifies instances where services such as EC2, Lambda, RDS, and others assume roles to obtain temporary credentials. While legitimate for standard operations, adversaries can exploit this behavior to escalate privileges or move laterally within an AWS environment. The technique involves leveraging existing service identities to gain access to resources beyond their intended scope. This rule is designed to detect anomalous or unauthorized role assumptions. The referenced detection rule was last updated on 2026-04-10 and analyzes AWS CloudTrail logs.

## Attack Chain

1. An attacker gains initial access to an AWS service, such as an EC2 instance, through methods like exploiting a vulnerable application running on the instance.
2. The attacker leverages the compromised service's existing IAM role or configurations.
3. The attacker uses the AWS STS AssumeRole API, using a service like EC2 or Lambda, to assume a different, more privileged role within the AWS environment.
4. The `AssumeRole` request includes the target role ARN (`aws.cloudtrail.resources.arn`) and a session name (`aws.cloudtrail.flattened.request_parameters.roleSessionName`), if available.
5. AWS STS validates the request based on IAM policies associated with the involved roles.
6. If successful, AWS STS provides temporary credentials, including an access key ID, secret access key, and session token (`aws.cloudtrail.flattened.response_elements.credentials.accessKeyId`).
7. The attacker uses the acquired temporary credentials to perform unauthorized actions, such as accessing sensitive data or modifying critical infrastructure.
8. The attacker moves laterally by assuming other roles or accessing other resources within the AWS environment, escalating their privileges to achieve their objectives.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, modification or deletion of critical infrastructure, and overall compromise of the AWS environment. The risk score associated with this behavior is 21, indicating a moderate level of potential damage. Lateral movement allows the attacker to expand their reach within the environment, potentially impacting multiple services and data stores. Organizations in any sector utilizing AWS services are potentially at risk.

## Recommendation

*   Deploy the Sigma rule "AWS Service Assuming Privileged Role" to detect unusual role assumption activities, focusing on the `aws.cloudtrail.user_identity.invoked_by` and `aws.cloudtrail.resources.arn` fields.
*   Investigate any alerts triggered by the Sigma rule, paying close attention to the user agent (`user_agent.original`) and the assumed role's permissions.
*   Enable AWS CloudTrail logging and ensure the logs are being ingested into your SIEM to provide the necessary data for the detection rules.
*   Create a baseline of legitimate role assumption activities by services in your environment to reduce false positives and improve the accuracy of the detection.
