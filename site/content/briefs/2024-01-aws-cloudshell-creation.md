---
title: AWS CloudShell Environment Creation Detection
slug: 2024-01-aws-cloudshell-creation
description: Detection of AWS CloudShell environment creation can indicate unauthorized command execution within AWS by an adversary leveraging a compromised console session to interact with AWS services.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - aws
  - cloudshell
  - execution
  - initial-access
vendors:
  - Amazon
products:
  - AWS CloudShell
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1059.009.html
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
rules:
  - title: AWS CloudShell Environment Created
    description: Detects the creation of a new AWS CloudShell environment, which can indicate unauthorized access and command execution within AWS infrastructure.
    platform: sigma
    severity: low
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.009
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudShell Activity Post Environment Creation
    description: Detects actions performed after a CloudShell environment is created, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.009
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

AWS CloudShell provides command-line access to AWS resources directly from the AWS Management Console. The `CreateEnvironment` API is called when a user launches CloudShell for the first time or accesses CloudShell in a new AWS region. An adversary with compromised console access may use CloudShell to execute commands, install tools, or interact with AWS services without needing local CLI credentials. This can occur even if MFA is enabled for the account if the adversary has already bypassed that control. Monitoring CloudShell environment creation helps detect unauthorized usage from compromised console sessions and is an indicator of potential malicious activity within the AWS environment. The rule focuses on detecting the initial creation of the CloudShell environment via the `CreateEnvironment` API call.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account through compromised credentials or a session hijack (T1078.004).
2. The attacker logs into the AWS Management Console using the compromised account (TA0001).
3. The attacker navigates to the CloudShell service within the AWS Management Console.
4. Since CloudShell hasn't been used before in the AWS region, the `CreateEnvironment` API is invoked (T1059.009).
5. The attacker uses the CloudShell environment to execute commands and scripts to enumerate AWS resources.
6. The attacker leverages the AWS CLI within CloudShell to create new IAM users or roles with elevated privileges.
7. The attacker uses CloudShell to deploy malicious code or modify existing cloud resources (e.g., S3 buckets, EC2 instances).
8. The attacker attempts to exfiltrate data or establish persistence within the AWS environment using the resources accessed and modified via CloudShell (TA0002).

## Impact

A successful attack can lead to unauthorized access to AWS resources, data exfiltration, privilege escalation, and deployment of malicious code within the AWS environment. This can result in data breaches, service disruptions, and financial losses. While the severity is rated low, successful exploitation can lead to significant downstream impact. The impact is highly dependent on the permissions associated with the compromised account used to access CloudShell.

## Recommendation

*   Deploy the Sigma rule `AWS CloudShell Environment Created` to detect the initial creation of CloudShell environments in your AWS environment.
*   Review `aws.cloudtrail.user_identity.arn` to identify the IAM principal that created the CloudShell environment.
*   Monitor CloudTrail logs for `CreateEnvironment` events to identify unauthorized CloudShell usage.
*   Consider restricting CloudShell access via SCPs or IAM policies for sensitive accounts.
*   Enable MFA for all console logins to reduce the risk of session compromise as mentioned in the overview.
*   Investigate surrounding activity for any IAM operations after CloudShell was accessed, as outlined in the "Triage and analysis" section of the rule description.
