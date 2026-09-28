---
title: Detection of Unauthorized AWS Lambda Function Deletion
slug: 2026-09-aws-lambda-deletion
description: This brief details a detection strategy for identifying the unauthorized deletion of AWS Lambda functions, a technique used by adversaries to disrupt operations, hide backdoors, or erase evidence.
date: "2026-09-28T10:09:41Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - lambda
  - cloudtrail
  - impact
vendors:
  - Amazon
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Adversaries may delete functions to disrupt business operations and automated workflows, to destroy attacker-deployed backdoors and remove evidence after achieving their objective.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
    evidence: Deleting a function removes its code, configuration, versions, and aliases.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_DeleteFunction.html
  - https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_lambda_function_deleted.toml
rules:
  - title: Detect AWS Lambda Function Deletion by Unusual User
    description: Detects the first time a given identity in an AWS account successfully deletes a Lambda function, potentially indicating malicious activity or unauthorized disruption.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1485
      - T1489
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for unauthorized function deletion.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific logic for AWS Lambda function monitoring.
  hunt_leads:
    - lead: Search for all successful 'DeleteFunction' events in CloudTrail logs from the past 30 days to establish a baseline of authorized users and automation tools.
      technique_id: T1485
      data_needed:
        - AWS CloudTrail logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: New Terms rule approach relies on historical baselining of user behavior.
  mitigation_plan:
    - priority: short_term
      action: Review and audit IAM policies to ensure the 'lambda:DeleteFunction' permission is restricted to trusted principals only.
      owner: IT Operations
      addresses: Unauthorized resource destruction
      evidence: Source documentation emphasizes restricting permissions as a remediation step.
---

Adversaries may delete AWS Lambda functions to disrupt business operations, destroy attacker-deployed backdoors, or remove evidence after achieving their objectives. Deleting a function is a destructive and often irreversible action that removes the code, configuration, published versions, and aliases of the function. This activity is frequently observed during security incidents where attackers attempt to inhibit incident response efforts or clean up their tracks. While legitimate Lambda function deletion occurs during routine environment teardowns, application decommissioning, and infrastructure-as-code (IaC) maintenance cycles, unexpected deletions performed by unauthorized principals should be flagged for review. Defenders can monitor AWS CloudTrail logs for 'DeleteFunction' events to identify potentially malicious activity, particularly when performed by principals that have not historically executed such operations.

## Impact

Successful unauthorized deletion of Lambda functions can result in the immediate disruption of critical serverless workloads and automated workflows. If the functions contain proprietary code or backdoors, their deletion can also hinder forensic investigations by destroying evidence of the attacker's activities. Organizations should maintain backups in source control or infrastructure-as-code repositories to ensure rapid recovery.

## Recommendation

- Implement the provided detection logic to monitor AWS CloudTrail logs for 'DeleteFunction' events, specifically focusing on identities that have not previously performed this action.
- Review and validate all Lambda function deletions that occur outside of approved change windows or maintenance periods.
- Constrain 'lambda:DeleteFunction' permissions to a minimal set of trusted IAM roles and service accounts to reduce the attack surface.
- Utilize IaC tools such as Terraform or Pulumi for function management and exclude these known service roles from the detection logic to reduce false positives.
- Ensure all Lambda code, configurations, and environment variables are stored in version-controlled repositories to facilitate rapid restoration after accidental or malicious deletion.
