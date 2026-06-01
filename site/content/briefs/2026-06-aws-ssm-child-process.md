---
title: AWS SSM Session Manager Child Process Execution
slug: 2026-06-aws-ssm-child-process
description: This rule detects process start events where the parent process is the AWS Systems Manager (SSM) Session Manager worker, which can indicate remote execution and lateral movement by adversaries abusing legitimate AWS credentials.
date: "2026-06-01T10:09:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ssm
  - execution
  - cloud
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
  - title: Detect AWS SSM Session Manager Child Processes - Generic
    description: Detects processes spawned by the AWS SSM session manager worker, indicating potential command execution within an SSM session.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
      - T1651
    data_sources:
      - process_creation
      - windows
  - title: Detect AWS SSM Session Manager Child Processes - Powershell
    description: Detects PowerShell scripts executed within an AWS SSM session manager.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1651
    data_sources:
      - process_creation
      - windows
  - title: Detect AWS SSM Session Manager Child Processes - Linux Shell
    description: Detects shell scripts executed within an AWS SSM session manager.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1651
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

The AWS Systems Manager (SSM) Session Manager provides interactive shell access to EC2 instances and hybrid nodes without requiring bastion hosts or open inbound ports. This capability is often leveraged legitimately for administrative purposes. However, adversaries can abuse SSM, using compromised AWS credentials and IAM permissions, to gain remote execution and facilitate lateral movement within a cloud environment. This involves initiating sessions on target instances and executing commands as child processes of the SSM Session Manager worker. Defenders should monitor process execution under the SSM session worker for unauthorized or malicious activity.

## Attack Chain

1. An adversary gains access to valid AWS credentials or an instance role with sufficient permissions, including `ssm:StartSession`.
2. The attacker uses the AWS CLI or API to initiate an SSM session to a target EC2 instance or hybrid node.
3. The SSM agent on the target instance starts a session worker process (e.g., `ssm-session-worker.exe` or `ssm-session-worker`).
4. The attacker executes commands or scripts within the SSM session. These commands are run as child processes of the session worker.
5. The attacker may perform reconnaissance activities, such as enumerating users, groups, or network configurations.
6. The attacker may attempt to download and execute malicious payloads or tools within the session.
7. The attacker leverages the compromised instance to pivot to other resources within the AWS environment.
8. The attacker achieves persistence, establishing a backdoor for long-term access and control.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, compromise of critical infrastructure, and lateral movement within the AWS environment. The lack of open inbound ports can make detection challenging. The impact scope depends on the IAM permissions of the compromised credentials or instance role. Depending on the permissions assigned, the attacker may be able to access other AWS resources and data.

## Recommendation

*   Deploy the Sigma rule "Detect AWS SSM Session Manager Child Processes - Generic" to identify suspicious processes spawned by the SSM session manager worker (process.parent.name).
*   Enable AWS CloudTrail logging and correlate timing with `StartSession`, `ResumeSession`, or related SSM API calls and the IAM principal that initiated the session.
*   Implement the Sigma rule "Detect AWS SSM Session Manager Child Processes - Powershell" to monitor for PowerShell scripts executed within an AWS SSM session manager (process.name : "powershell.exe" and process.args : *awsrunPowerShellScript*).
