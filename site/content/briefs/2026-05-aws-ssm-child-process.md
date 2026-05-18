---
title: AWS SSM Session Manager Child Process Execution
slug: 2026-05-aws-ssm-child-process
description: This rule identifies process start events where the parent process is the AWS Systems Manager (SSM) Session Manager worker, which adversaries may abuse for remote execution and lateral movement using legitimate AWS credentials and IAM permissions.
date: "2026-05-18T09:45:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - execution
  - lateral-movement
vendors:
  - Amazon
products:
  - AWS Systems Manager
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
references:
  - https://www.mitiga.io/blog/abusing-the-amazon-web-services-ssm-agent-as-a-remote-access-trojan
  - https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/
  - https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html
rules:
  - title: AWS SSM Session Manager Child Process Execution - Generic
    description: Detects process execution where the parent process is the AWS Systems Manager (SSM) Session Manager worker.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
  - title: AWS SSM Session Manager Child Process Execution - Linux
    description: Detects process execution where the parent process is the AWS Systems Manager (SSM) Session Manager worker on Linux systems.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - linux
  - title: AWS SSM Session Manager - PowerShell or Shell via awsrun Script
    description: Detects PowerShell or Shell execution with arguments indicating the use of awsrunPowerShellScript or awsrunShellScript within AWS SSM Session Manager, used for remote command execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.004
      - T1651
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

The AWS Systems Manager (SSM) Session Manager provides interactive shell access to EC2 instances and hybrid nodes without requiring bastion hosts or open inbound ports. This capability is legitimately used by administrators for managing their AWS infrastructure. However, adversaries can abuse Session Manager for remote execution and lateral movement within an AWS environment if they obtain valid AWS credentials and IAM permissions that allow `ssm:StartSession` or related API calls. This attack vector allows them to execute commands as child processes of the SSM session worker. This activity can be difficult to detect due to the use of legitimate AWS services.

## Attack Chain

1.  Adversary gains access to AWS credentials with `ssm:StartSession` permissions, possibly through credential harvesting or compromised EC2 instance roles.
2.  Adversary uses the AWS CLI or API to initiate an SSM Session Manager session to a target EC2 instance or managed node.
3.  The `ssm-session-worker` process is started on the target host.
4.  Adversary executes commands within the SSM session, which manifest as child processes of `ssm-session-worker`.
5.  The executed commands may involve reconnaissance activities, such as gathering system information or network configuration.
6.  The adversary may attempt to download malicious payloads or tools to the compromised instance.
7.  The adversary uses the compromised host as a pivot point for lateral movement to other AWS resources.
8.  Adversary achieves their objective, such as data exfiltration or deployment of malware.

## Impact

Successful exploitation allows an attacker to gain unauthorized access to EC2 instances and managed nodes within an AWS environment. This can lead to data breaches, system compromise, and disruption of services. The abuse of legitimate AWS services like SSM Session Manager can make detection more challenging, potentially prolonging the attacker's dwell time.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious child processes of the AWS SSM Session Manager worker.
*   Monitor AWS CloudTrail logs for `StartSession`, `ResumeSession`, or related SSM API calls to identify the IAM principal initiating sessions (reference: Investigating AWS SSM Session Manager Child Process Execution section).
*   Implement strict IAM policies and least privilege principles to limit which users and roles have permissions to start SSM sessions.
*   Review SSM and VPC endpoint policies to ensure they are configured securely (reference: Response and remediation section).
