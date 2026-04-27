---
title: AWS STS Role Assumption by User
slug: 2026-03-aws-sts-role-assumption
description: Detection of a user assuming a role in AWS Security Token Service (STS) to obtain temporary credentials, which can indicate privilege escalation or lateral movement.
date: "2026-03-04T18:01:49Z"
severities:
  - low
tags:
  - aws
  - privilege-escalation
  - lateral-movement
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
  - https://attack.mitre.org/techniques/T1550/
  - https://attack.mitre.org/techniques/T1550/001/
rules:
  - title: AWS STS AssumeRole Activity by IAM User
    description: Detects when an IAM user assumes a role in AWS STS to obtain temporary credentials, potentially indicating privilege escalation or lateral movement.
    platform: sigma
    severity: low
    tactics:
      - lateral_movement
      - privilege_escalation
    techniques:
      - T1548
      - T1550
      - T1550.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS STS AssumeRole with Uncommon User Agent
    description: Detects when an IAM user assumes a role in AWS STS using an uncommon user agent, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
      - privilege_escalation
    techniques:
      - T1548
      - T1550
      - T1550.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection rule identifies when an IAM user assumes a role in AWS Security Token Service (STS) within an AWS environment. The AWS Security Token Service (STS) allows users to request temporary, limited-privilege credentials for accessing AWS resources. While legitimate role assumption is common for authorized access, adversaries can abuse this mechanism to escalate privileges or move laterally within a compromised AWS account. This behavior is detected by monitoring AWS CloudTrail logs for…
