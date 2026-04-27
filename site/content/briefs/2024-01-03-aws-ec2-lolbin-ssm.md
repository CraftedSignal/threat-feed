---
title: AWS EC2 LOLBin Execution via SSM SendCommand
slug: 2024-01-03-aws-ec2-lolbin-ssm
description: Detection of Living Off the Land Binaries (LOLBins) or GTFOBins execution on EC2 instances via AWS Systems Manager (SSM) SendCommand API, potentially indicating malicious activity.
date: "2026-04-10T16:27:52Z"
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

This threat brief focuses on detecting the execution of Living Off the Land Binaries (LOLBins) or GTFOBins on Amazon EC2 instances via AWS Systems Manager (SSM) `SendCommand` API. The technique involves correlating AWS CloudTrail `SendCommand` events with endpoint process execution by matching SSM command IDs. While AWS redacts command parameters in CloudTrail logs, this correlation technique reveals the actual commands executed on EC2 instances. This is critical because adversaries may abuse…
