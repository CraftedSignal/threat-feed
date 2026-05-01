---
title: AWS SSM Session Manager Child Process Execution Abuse
slug: 2024-01-aws-ssm-session-manager-abuse
description: Adversaries abuse AWS Systems Manager (SSM) Session Manager to gain remote execution and lateral movement within AWS environments by spawning malicious child processes from the SSM session worker, leveraging legitimate AWS credentials and IAM permissions.
date: "2026-05-01T20:57:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ssm
  - session-manager
  - execution
  - cloud
vendors:
  - Amazon
products:
  - AWS Systems Manager Session Manager
affected_os:
  - Linux
  - Windows
  - macOS
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
  - title: Detect AWS SSM Session Manager Child Process Execution (Generic)
    description: Detects process execution where the parent process is the AWS SSM Session Manager worker, indicating potential abuse for remote execution and lateral movement.
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
  - title: Detect AWS SSM Session Manager Child Process Execution (Linux)
    description: Detects process execution where the parent process is the AWS SSM Session Manager worker on Linux, indicating potential abuse for remote execution and lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
      - T1651
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

AWS Systems Manager (SSM) Session Manager provides interactive shell access to EC2 instances and hybrid nodes without the need for bastion hosts or open inbound ports. Attackers can abuse this functionality by leveraging compromised AWS credentials or IAM roles with `ssm:StartSession` permissions to gain unauthorized access to target systems. This allows for remote execution of commands and lateral movement within the AWS environment. The technique involves spawning child processes from the SSM session worker process to perform malicious activities. Defenders should monitor for unusual process execution patterns originating from SSM sessions to identify potential abuse.

## Attack Chain

1.  Attacker gains access to valid AWS credentials or IAM role with `ssm:StartSession` permissions.
2.  Attacker initiates an SSM session to a target EC2 instance or hybrid node using the compromised credentials.
3.  The `ssm-session-worker` process is started on the target instance to manage the interactive session.
4.  Attacker executes commands within the session, spawning child processes from the `ssm-session-worker` process.
5.  Attacker may use scripting languages such as PowerShell or Bash to execute malicious code (e.g., using `awsrunPowerShellScript` or `awsrunShellScript`).
6.  These scripts perform reconnaissance, download additional tools, or attempt credential access.
7.  Attacker moves laterally to other instances or resources within the AWS environment.
8.  The ultimate objective is often data exfiltration, privilege escalation, or maintaining persistent access.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, compromise of critical systems, and lateral movement within the AWS environment. The impact can range from data breaches to complete control of the compromised infrastructure. The number of affected systems depends on the scope of the compromised credentials and the attacker's ability to move laterally. Organizations using AWS SSM are at risk.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious child processes spawned by `ssm-session-worker`.
*   Correlate process activity with AWS CloudTrail logs for `StartSession` and related API calls to identify the IAM principal initiating the session (see the overview section for API names).
*   Implement strict IAM policies and regularly review AWS credentials to minimize the risk of credential compromise.
*   Monitor `process.command_line`, `process.executable`, `process.user.name` for unusual activity within SSM sessions.
