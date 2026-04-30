---
title: AWS EC2 LOLBin Execution via SSM SendCommand
slug: 2024-01-03-aws-ec2-lolbin-ssm
description: Detection of Living Off the Land Binaries (LOLBins) or GTFOBins execution on EC2 instances via AWS Systems Manager (SSM) SendCommand API, potentially indicating malicious activity.
date: "2026-04-10T16:27:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ec2
  - ssm
  - lolbin
  - execution
  - cloud
mitre_ttps:
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
  - https://www.kali.org/tools/pacu/
  - https://www.100daysofredteam.com/p/ghost-in-the-cloud-abusing-aws-ssm
  - https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/
  - https://gtfobins.github.io/
rules:
  - title: Detect AWS EC2 LOLBin Execution via SSM SendCommand
    description: Detects the execution of LOLBins on EC2 instances via AWS SSM SendCommand.
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
  - title: Detect AWS SSM Shell Script Execution
    description: Detects the execution of shell scripts launched by the AWS SSM agent.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1651
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This threat brief focuses on detecting the execution of Living Off the Land Binaries (LOLBins) or GTFOBins on Amazon EC2 instances via AWS Systems Manager (SSM) `SendCommand` API. The technique involves correlating AWS CloudTrail `SendCommand` events with endpoint process execution by matching SSM command IDs. While AWS redacts command parameters in CloudTrail logs, this correlation technique reveals the actual commands executed on EC2 instances. This is critical because adversaries may abuse SSM to execute malicious commands remotely without requiring SSH or RDP access. They can leverage legitimate system utilities for various malicious purposes, including data exfiltration, establishing reverse shells, or facilitating lateral movement within the cloud environment. The rule was last updated on 2026-04-10.

## Attack Chain

1. An attacker gains initial access to AWS via compromised credentials or an exposed IAM role.
2. The attacker uses the AWS CLI or API to initiate an SSM `SendCommand` to a target EC2 instance. The `DocumentName` parameter is set to `AWS-RunShellScript`.
3. The SSM agent on the EC2 instance receives the `SendCommand` request.
4. The SSM agent executes a shell script (`_script.sh`) within a dedicated directory for orchestration.
5. The shell script executes a LOLBin, such as `curl`, `wget`, `python`, or `perl`, to perform malicious actions. The parent process of the LOLBin will be the SSM shell script.
6. The LOLBin is used to download a malicious payload, establish a reverse shell, or exfiltrate data.
7. The attacker uses the established reverse shell to perform further actions on the EC2 instance.

## Impact

Successful exploitation can lead to unauthorized access to EC2 instances, data exfiltration, deployment of malware, and lateral movement within the AWS environment. Although a number of impacted organizations is not available, this attack is able to bypass traditional network security controls. Organizations in any sector utilizing AWS EC2 instances and SSM are potentially at risk. The lack of required SSH or RDP access makes this technique particularly stealthy.

## Recommendation

*   Enable AWS CloudTrail logging to capture `SendCommand` events and monitor for `AWS-RunShellScript` in the `request_parameters`.
*   Deploy the Sigma rule "Detect AWS EC2 LOLBin Execution via SSM SendCommand" to your SIEM and tune for your environment.
*   Monitor endpoint process execution logs for the execution of LOLBins like `curl`, `wget`, `python`, `perl`, `nc`, etc., with parent processes related to SSM.
*   Implement strict IAM policies to restrict SSM `SendCommand` permissions to only authorized users and roles.
*   Review and audit existing SSM configurations to identify and remediate any overly permissive settings.
