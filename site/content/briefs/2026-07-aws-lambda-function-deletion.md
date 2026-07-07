---
title: AWS Lambda Function Deletion
slug: 2026-07-aws-lambda-function-deletion
description: Adversaries may delete AWS Lambda functions to disrupt business operations, remove evidence of their presence, or impede incident response, an action detectable by monitoring for `DeleteFunction` calls in `aws.cloudtrail` logs and correlating with expected change windows.
date: "2026-07-03T16:17:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - lambda
  - impact
  - data-destruction
  - service-stop
vendors:
  - AWS
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Deleting a function removes its code, configuration, versions, and aliases. Adversaries may delete functions...to destroy attacker-deployed backdoors and remove evidence after achieving their objective.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
    evidence: Adversaries may delete functions to disrupt business operations and automated workflows...or to inhibit incident response.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_DeleteFunction.html
  - https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html
rules:
  - title: AWS Lambda Function Deletion
    description: Detects the deletion of an AWS Lambda function, an action adversaries may perform to disrupt services, remove evidence, or inhibit incident response.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1485
      - T1489
    data_sources:
      - audit
      - aws.cloudtrail
rules_count: 1
---

This brief details the potential malicious deletion of AWS Lambda functions, a critical cloud impact technique. Threat actors, after gaining unauthorized access to an AWS environment, may delete Lambda functions to achieve several objectives: disrupt critical business operations and automated workflows, destroy attacker-deployed backdoors to remove evidence of their activities, or inhibit incident response by eliminating essential components of the victim's infrastructure. Such deletions are destructive and often irreversible without meticulous redeployment, making them a significant concern for defenders. While legitimate deletions occur during application decommissioning or infrastructure-as-code cycles, unauthorized deletions represent a significant compromise and indicate a severe impact on the targeted organization's cloud resources and operational continuity.

## Impact

The unauthorized deletion of AWS Lambda functions can lead to severe operational disruptions, causing outages for serverless applications, breaking automated workflows, and rendering essential services inoperable. If attackers delete functions that were part of their command and control infrastructure or persistence mechanisms, it serves to destroy evidence of their presence, complicating forensic analysis and incident recovery efforts. Furthermore, the deletion of critical infrastructure components or security-related functions can actively inhibit incident response teams from effectively containing or remediating a breach, prolonging the attacker's dwell time and increasing potential damages.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `DeleteFunction` calls in AWS CloudTrail logs and ensure immediate alerting for unauthorized activity.
*   Investigate the `aws.cloudtrail.user_identity.arn`, `source.ip`, and `user_agent.original` fields from the Sigma rule's log source to identify the principal performing the deletion and the method used.
*   Inspect `aws.cloudtrail.request_parameters.functionName` (as seen in the rule's positive test data) to understand which specific function was deleted and its associated application or environment.
*   Correlate `aws.cloudtrail` events with your organization's change management records to determine if a deletion aligns with an approved maintenance or deployment window.
*   Implement filtering within your SIEM for known and approved deployment roles or CI/CD pipelines (e.g., specific `aws.cloudtrail.user_identity.arn` values) that legitimately perform Lambda function deletions to reduce false positives.
*   If an unauthorized deletion is confirmed, restore the affected Lambda function from a known-good source or infrastructure-as-code definition and verify its configuration and execution role.
*   Rotate or restrict credentials for the compromised principal if illicit activity is suspected, and enforce the principle of least privilege by limiting `lambda:DeleteFunction` permissions to a minimal set of trusted roles.
