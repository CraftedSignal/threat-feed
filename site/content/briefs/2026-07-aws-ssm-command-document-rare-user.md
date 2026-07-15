---
title: AWS SSM Command Document Created by Rare User
slug: 2026-07-aws-ssm-command-document-rare-user
description: Adversaries may leverage AWS Systems Manager (SSM) command document creation by rare or unusual users to execute arbitrary commands on managed instances, potentially leading to unauthorized access, command and control, or data exfiltration.
date: "2026-07-15T14:04:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - execution
vendors:
  - Amazon
products:
  - AWS Systems Manager
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
    evidence: Adversaries may create SSM command documents to execute commands on managed instances, potentially leading to unauthorized access, command and control, data exfiltration and more.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/execution_ssm_command_document_created_by_rare_user.toml
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_CreateDocument.html
  - https://docs.aws.amazon.com/systems-manager/latest/userguide/documents.html
rules:
  - title: Detect AWS SSM Command Document Creation
    description: Detects when an AWS Systems Manager (SSM) command document is created. This rule should be tuned to identify creation by users or roles that do not typically perform this action, as adversaries may use this to execute commands on managed instances.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1651
    data_sources:
      - cloud
      - aws
      - cloudtrail
rules_count: 1
---

This threat brief details how adversaries exploit compromised AWS identities to create malicious AWS Systems Manager (SSM) Command documents, a technique often observed through the `CreateDocument` API call made by users or roles that do not typically perform this action. Elastic's detection rule highlights this activity as a high-severity threat, indicating potential unauthorized access, command and control, and data exfiltration within an AWS environment. While the creation of SSM command documents can be legitimate for administrative purposes, detection of this action by an anomalous user or role signals a critical security event. Defenders should pay close attention to `CreateDocument` events where the `documentType` is "Command" and correlate these with the calling identity's historical activity and the content of the created document.

## Attack Chain

1. An adversary gains initial access to an AWS account, potentially through compromised user credentials, an insecure API key, or an exploited web application.
2. The adversary identifies a compromised AWS Identity and Access Management (IAM) user or role that possesses the necessary permissions to create AWS Systems Manager (SSM) documents.
3. The adversary invokes the `CreateDocument` API call, using the compromised identity, to generate a new SSM document. This document is specifically crafted with `documentType: Command` and embeds malicious commands for execution.
4. The malicious SSM Command document is designed to achieve adversary objectives, such as executing reconnaissance commands, establishing persistence, escalating privileges, or initiating data exfiltration.
5. Subsequently, the adversary utilizes the `SendCommand` API call to deploy and execute this newly created malicious SSM Command document on targeted AWS managed instances within the scope of the compromised identity's permissions.
6. The commands embedded within the SSM document are executed on the targeted instances, allowing the adversary to achieve objectives such as unauthorized access, maintaining command and control, or exfiltrating sensitive data.

## Impact

Successful exploitation allows adversaries to execute arbitrary commands with the privileges of the compromised AWS identity on managed instances. This can lead to a range of severe consequences, including full compromise of affected instances, persistent unauthorized access, establishment of covert command and control channels, and large-scale data exfiltration from an organization's AWS environment. The impact extends to operational disruption, potential intellectual property theft, and regulatory non-compliance. Without timely detection, attackers can expand their footprint across the cloud infrastructure, affecting numerous systems and data stores.

## Recommendation

* Deploy the Sigma rule "Detect AWS SSM Command Document Created" provided in this brief to your SIEM and tune for your environment.
* Ensure AWS CloudTrail logging is enabled and configured to capture `CreateDocument` API calls for the `ssm.amazonaws.com` service, specifically focusing on `event.action: "CreateDocument"` and `event.outcome: "success"`.
* Restrict permissions for `ssm:CreateDocument` and `ssm:SendCommand` to only trusted IAM users and roles that genuinely require this capability for administrative tasks.
* Implement an alert for high-risk `CreateDocument` events by reviewing the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.request_parameters.name` fields to identify unauthorized document creation.
* For any detected suspicious activity, immediately review the document's content (`aws.cloudtrail.request_parameters.content`) if available in logs, or via the AWS Management Console, and delete unauthorized documents.
