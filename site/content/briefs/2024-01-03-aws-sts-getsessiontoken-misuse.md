---
title: Suspicious AWS STS GetSessionToken Usage
slug: 2024-01-03-aws-sts-getsessiontoken-misuse
description: The AWS STS GetSessionToken API is being misused to create temporary tokens for lateral movement and privilege escalation within AWS environments by potentially compromised IAM users.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud
  - lateral-movement
  - privilege-escalation
  - sts
  - GetSessionToken
vendors:
  - Amazon
products:
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Lateral Movement
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/elastic/detection-rules/pull/1213
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_sts_getsessiontoken_misuse.yml
rules:
  - title: AWS STS GetSessionToken Misuse
    description: Identifies the suspicious use of GetSessionToken. Tokens could be created and used by attackers to move laterally and escalate privileges.
    platform: sigma
    severity: low
    tactics:
      - lateral-movement
      - privilege-escalation
    techniques:
      - T1548
      - T1550
      - T1550.001
    data_sources:
      - aws
      - cloudtrail
  - title: AWS STS GetSessionToken with MFA
    description: Identifies the usage of GetSessionToken with MFA serial number. If MFA is not enforced in your organization it might hint at suspicious activity.
    platform: sigma
    severity: informational
    tactics:
      - lateral-movement
      - privilege-escalation
    techniques:
      - T1548
      - T1550
      - T1550.001
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

The AWS Security Token Service (STS) GetSessionToken API allows IAM users to create temporary security credentials. Attackers can abuse this functionality by generating tokens with elevated privileges or for lateral movement within an AWS environment if an IAM user's credentials have been compromised. This activity can be difficult to detect as GetSessionToken is a legitimate function, but unusual patterns or IAM users generating tokens where it is not expected should be investigated. This activity is of particular concern because it bypasses normal IAM role assumption logging and creates a separate credential for an attacker to abuse, making access more difficult to track. The impact is significant, allowing attackers to perform actions as the compromised IAM user or escalate privileges.

## Attack Chain

1.  An attacker gains initial access to an AWS environment, potentially through compromised IAM user credentials.
2.  The attacker authenticates to AWS using the compromised IAM user credentials.
3.  The attacker calls the STS GetSessionToken API, specifying desired permissions or roles (if permitted by the IAM user's policies).
4.  AWS STS generates a new set of temporary credentials (access key ID, secret access key, and session token).
5.  The attacker configures their AWS CLI or SDK to use the newly acquired temporary credentials.
6.  The attacker leverages these temporary credentials to perform actions within the AWS environment, potentially escalating privileges or moving laterally.
7.  The attacker covers their tracks by deleting the CloudTrail logs.
8.  The attacker exfiltrates sensitive data, deploys malware, or causes disruption within the AWS environment using the acquired privileges.

## Impact

Compromised AWS environments can lead to data breaches, service disruptions, and financial losses. Successful exploitation via GetSessionToken misuse allows attackers to move laterally, escalate privileges, and perform unauthorized actions within the AWS infrastructure. The number of affected organizations is currently unknown, but any organization relying on AWS is potentially at risk. If successful, attackers can steal sensitive data, compromise critical systems, and disrupt business operations.

## Recommendation

*   Deploy the Sigma rule "AWS STS GetSessionToken Misuse" to your SIEM to detect suspicious GetSessionToken API calls (see rules section).
*   Investigate GetSessionToken calls where `userIdentity.type` is `IAMUser` to determine if the request is legitimate.
*   Monitor CloudTrail logs for unusual patterns of GetSessionToken usage, particularly from unfamiliar user agents or hosts.
*   Implement strong IAM policies and MFA to minimize the risk of compromised IAM user credentials.
*   Review the false positives section of the Sigma rule to tune the rule for your specific environment.
