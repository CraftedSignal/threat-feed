---
title: AWS EC2 Instance Console Login via Assumed Role
slug: 2024-10-aws-ec2-console-login
description: An AWS EC2 instance's assumed role is used to login to the AWS Management Console, potentially indicating credential theft and lateral movement.
date: "2024-10-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - lateral-movement
  - credential-access
vendors:
  - AWS
products:
  - EC2
  - IAM
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://redcanary.com/blog/aws-sts/
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html/
  - https://github.com/aws-samples/aws-incident-response-playbooks/blob/c151b0dc091755fffd4d662a8f29e2f6794da52c/playbooks/
  - https://github.com/aws-samples/aws-customer-playbook-framework/tree/a8c7b313636b406a375952ac00b2d68e89a991f2/docs
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS EC2 Instance Console Login via Assumed Role
    description: Detects successful AWS Management Console or federation login activity performed using an EC2 instance’s assumed role credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - lateral_movement
    techniques:
      - T1021.007
      - T1552.005
    data_sources:
      - webserver
      - linux
  - title: AWS EC2 Instance Console Login without MFA
    description: Detects AWS EC2 instance console login via assumed role without MFA.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - lateral_movement
    techniques:
      - T1021.007
      - T1552.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This detection identifies a highly unusual event: a successful AWS Management Console or federation login using an EC2 instance's assumed role credentials. Typically, EC2 instances leverage temporary credentials exclusively for programmatic API calls, bypassing interactive console authentication. The anomalous "ConsoleLogin" or "GetSigninToken" event, characterized by a session pattern incorporating "i-" (the EC2 instance ID), raises concerns about potential credential compromise. An adversary might have illicitly obtained the instance's temporary credentials from the Instance Metadata Service (IMDS), version 1 or 2, and is attempting to use them for console access. This activity can enable lateral movement, privilege escalation, or persistence within the AWS account.

## Attack Chain

1.  Attacker gains initial access to a vulnerable EC2 instance, possibly via an unpatched application or exposed service.
2.  Attacker exploits the EC2 instance to access the Instance Metadata Service (IMDS) endpoint at `169.254.169.254`.
3.  Attacker retrieves temporary STS credentials associated with the EC2 instance's IAM role using the IMDS API.
4.  Attacker leverages the retrieved credentials to authenticate to the AWS Management Console or a federated login.
5.  The "ConsoleLogin" or "GetSigninToken" event is logged by CloudTrail with the user identity reflecting the assumed role and the instance ID.
6.  Attacker uses the console to perform reconnaissance, identify additional resources, and enumerate IAM permissions.
7.  Attacker attempts to laterally move to other AWS services or EC2 instances by assuming other roles or creating new IAM users.
8.  Attacker establishes persistence by modifying IAM policies, creating new users with elevated privileges, or deploying backdoors within the AWS environment.

## Impact

Successful exploitation could lead to a complete compromise of the AWS environment. An attacker could escalate privileges, gain access to sensitive data stored in S3 buckets or databases, disrupt critical services, and deploy ransomware. The number of victims would depend on the permissions granted to the compromised IAM role, potentially affecting all resources within the AWS account.

## Recommendation

*   Deploy the Sigma rule `AWS EC2 Instance Console Login via Assumed Role` to your SIEM and tune for your environment to detect this anomalous login behavior.
*   Enforce IMDSv2 on all EC2 instances to mitigate credential harvesting from the metadata service as mentioned in the overview.
*   Implement restrictive IAM policies, denying console access (`iam:PassRole`, `sts:GetFederationToken`) for non-human roles.
*   Revoke temporary credentials for the affected role (`aws sts revoke-session-token`) if this activity is detected.
*   Monitor CloudTrail logs for requests to `169.254.169.254` from unauthorized binaries or users to identify potential IMDS exploitation as per the investigation steps.
