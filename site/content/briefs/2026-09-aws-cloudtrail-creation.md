---
title: Monitoring AWS CloudTrail Creation for Unauthorized Log Diversion
slug: 2026-09-aws-cloudtrail-creation
description: Adversaries may use the CreateTrail API to establish unauthorized logging configurations that redirect audit data to attacker-controlled destinations or circumvent existing monitoring controls.
date: "2026-09-18T19:24:52Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - log-auditing
vendors:
  - Amazon
products:
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Adversaries may create new trails to capture sensitive data or cover their tracks.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries may create new trails to capture sensitive data or cover their tracks.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_CreateTrail.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/create-trail.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/collection_cloudtrail_logging_created.toml
rules:
  - title: Detect AWS CloudTrail Log Created
    description: Detects creation of a new AWS CloudTrail trail via the CreateTrail API. Unauthorized trails should be validated for destination ownership and audit scope.
    platform: sigma
    severity: low
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1530
      - T1562.008
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for CreateTrail events
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 594e0cbf-86cc-45aa-9ff7-ff27db27d3ed provided in source
  mitigation_plan:
    - priority: immediate
      action: Review IAM policies to restrict cloudtrail:CreateTrail to authorized admins
      owner: IT Operations
      addresses: T1562.008
      evidence: Source hardening section
---

The creation of new AWS CloudTrail trails is a critical security event that requires rigorous validation to ensure account integrity. While often associated with legitimate administrative onboarding or architectural changes, malicious actors utilize the `CreateTrail` API to deploy secondary trails. These trails can be configured to exfiltrate logs to attacker-controlled S3 buckets, limit regions to avoid detection of cross-region activity, or exclude specific event types to hide illicit actions. 

Defenders must ensure that all new trails align with organizational standards, specifically regarding destination ownership, mandatory encryption using approved Customer Master Keys (CMKs), and multi-region coverage. Failure to monitor these API calls can lead to significant blind spots, as attackers may disable or subvert existing logging mechanisms while establishing their own persistent visibility into the environment. This intelligence highlights the need for continuous auditing of `CreateTrail` events to identify and remediate unauthorized modifications to cloud logging architecture.

## Impact

Successful exploitation of cloud logging configurations enables attackers to exfiltrate sensitive operational data, mask malicious activity from security teams, and maintain persistent, stealthy access to cloud infrastructure. Unauthorized trails can redirect logs to external accounts, effectively compromising the organization's compliance posture and incident response capabilities, potentially resulting in data breach and loss of administrative control over AWS resources.

## Recommendation

* Implement the following Sigma rule to detect `CreateTrail` API activity and integrate it into your SIEM pipeline for immediate triage.
* Restrict the `cloudtrail:CreateTrail` permission to authorized administrative IAM roles using IAM policies and Service Control Policies (SCPs).
* Use AWS Config or Security Hub to enforce organizational compliance standards, such as mandatory multi-region logging and valid destination buckets.
* Establish a manual review process for all new CloudTrail configurations to verify destination ownership and encryption settings before they are accepted as part of the baseline.
