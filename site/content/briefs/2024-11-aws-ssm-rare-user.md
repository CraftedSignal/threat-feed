---
title: AWS SSM Command Document Created by Rare User
slug: 2024-11-aws-ssm-rare-user
description: An AWS Systems Manager (SSM) command document creation by a user or role who does not typically perform this action, which can lead to unauthorized access, command and control, or data exfiltration.
date: "2026-04-10T16:27:52Z"
severities:
  - low
tags:
  - cloud
  - aws
  - ssm
  - execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
references:
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_CreateDocument.html
  - https://docs.aws.amazon.com/systems-manager/latest/userguide/documents.html
rules:
  - title: AWS SSM Command Document Created by Rare User
    description: Detects when an AWS SSM command document is created by a user or role that is not typically associated with this activity.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1651
    data_sources:
      - cloudtrail
      - aws
  - title: AWS SSM SendCommand API Call
    description: Detects usage of the SendCommand API call which may indicate SSM document execution.
    platform: sigma
    severity: informational
    tactics:
      - execution
    techniques:
      - T1651
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This rule identifies when an AWS Systems Manager (SSM) command document is created by a user or role who does not typically perform this action. The rule focuses on detecting anomalous creation of SSM command documents. Adversaries may create SSM command documents to execute commands on managed instances, potentially leading to unauthorized access, command and control, and data exfiltration. The rule utilizes AWS CloudTrail logs to monitor the `CreateDocument` API call within the SSM service…
