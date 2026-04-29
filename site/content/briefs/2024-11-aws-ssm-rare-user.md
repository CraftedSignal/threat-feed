---
title: AWS SSM Command Document Created by Rare User
slug: 2024-11-aws-ssm-rare-user
description: An AWS Systems Manager (SSM) command document creation by a user or role who does not typically perform this action, which can lead to unauthorized access, command and control, or data exfiltration.
date: "2026-04-10T16:27:52Z"
type: coverage
types:
  - coverage
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

This rule identifies when an AWS Systems Manager (SSM) command document is created by a user or role who does not typically perform this action. The rule focuses on detecting anomalous creation of SSM command documents. Adversaries may create SSM command documents to execute commands on managed instances, potentially leading to unauthorized access, command and control, and data exfiltration. The rule utilizes AWS CloudTrail logs to monitor the `CreateDocument` API call within the SSM service. This activity is flagged when the user or role creating the document deviates from established patterns, indicating a potential security risk. This detection is relevant for organizations using AWS SSM for managing their infrastructure and aims to prevent unauthorized command execution on managed instances.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or an exposed IAM role.
2. The attacker attempts to create a new SSM Command document using the `CreateDocument` API call.
3. The `CreateDocument` API call is logged by AWS CloudTrail with details about the user identity, request parameters, and document description.
4. The detection rule analyzes CloudTrail logs, specifically looking for the `CreateDocument` event with a document type of `Command`.
5. The rule identifies the user or role associated with the `CreateDocument` API call by inspecting the `aws.cloudtrail.user_identity.arn` field.
6. If the user or role is considered rare or unusual for creating SSM Command documents within the organization, the rule triggers an alert.
7. The attacker could then use the created document to execute arbitrary commands on managed instances.
8. Successful execution of these commands leads to various impacts, including unauthorized access, command and control, data exfiltration, or disruption of services.

## Impact

The successful exploitation of this technique can lead to unauthorized access to AWS resources, potentially affecting all systems managed by AWS SSM in the targeted environment. The creation of malicious SSM command documents can lead to data exfiltration, system compromise, or denial of service. If successful, this can impact hundreds or thousands of systems depending on the scope of AWS SSM usage in the organization.

## Recommendation

*   Deploy the Sigma rule "AWS SSM Command Document Created by Rare User" to your SIEM, ensuring proper indexing of CloudTrail logs (index = \["filebeat-\*", "logs-aws.cloudtrail-\*"]).
*   Review the `aws.cloudtrail.request_parameters.content` field in the CloudTrail logs for any suspicious commands within the created SSM document.
*   Restrict SSM document creation permissions to specific, trusted roles or users to prevent unauthorized document creation as mentioned in the overview.
*   Monitor the `SendCommand` API call related to the created SSM document to see if it is used to execute commands on managed instances, as described in the triage section.
