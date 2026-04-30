---
title: AWS STS AssumeRole Misuse for Lateral Movement and Privilege Escalation
slug: 2024-01-aws-assumerole-misuse
description: Abuse of AWS STS AssumeRole can allow attackers to move laterally within an AWS environment and escalate privileges, potentially leading to unauthorized access to sensitive resources and data.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.lateral-movement
  - attack.privilege-escalation
  - attack.t1548
  - attack.t1550
  - attack.t1550.001
vendors:
  - Amazon
products:
  - AWS STS
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Credentials
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://github.com/elastic/detection-rules/pull/1214
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_sts_assumerole_misuse.yml
rules:
  - title: AWS STS AssumeRole Misuse Detection
    description: Detects suspicious use of AssumeRole, which could indicate lateral movement or privilege escalation attempts.
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
rules_count: 1
---

The AWS Security Token Service (STS) AssumeRole function allows users or applications to assume a different IAM role, granting temporary access to resources and permissions associated with that role.  Attackers who gain initial access to an AWS account can misuse AssumeRole to move laterally to other roles and escalate their privileges. This can occur if the initial role has overly permissive trust relationships or if an attacker can manipulate the role assumption process.  This activity is detected through CloudTrail logs that record the AssumeRole event. The impact of this activity can be significant, depending on the permissions associated with the roles assumed.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or an exploited vulnerability.
2. The attacker identifies IAM roles within the AWS environment that they may be able to assume.
3. The attacker attempts to use the `AssumeRole` API call to assume a different role. This call includes parameters specifying the target role ARN and a session name.
4. AWS STS validates the request.  Successful validation depends on the trust policy of the target role and the permissions of the initial user or role.
5. If the validation is successful, AWS STS returns temporary security credentials (access key ID, secret access key, and session token) to the attacker.
6. The attacker uses these temporary credentials to access AWS resources and perform actions authorized by the assumed role.
7. The attacker continues to move laterally and escalate privileges by assuming additional roles.
8. The attacker achieves their objective, such as accessing sensitive data, modifying configurations, or disrupting services.

## Impact

Successful exploitation can lead to a wide range of impacts, including unauthorized access to sensitive data stored in S3 buckets or databases, modification or deletion of critical infrastructure configurations, and disruption of AWS services. The scope of the impact depends on the permissions associated with the roles that the attacker is able to assume. This can affect any organization using AWS, and the consequences can range from data breaches and financial losses to reputational damage and regulatory penalties.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune for your environment to detect suspicious `AssumeRole` activity based on `userIdentity.type` and `userIdentity.sessionContext.sessionIssuer.type`.
*   Review and harden IAM role trust policies to ensure that only authorized entities can assume roles.
*   Monitor CloudTrail logs for unusual patterns of `AssumeRole` API calls, especially those originating from unfamiliar user identities or locations.
*   Implement multi-factor authentication (MFA) for all IAM users to reduce the risk of credential compromise.
