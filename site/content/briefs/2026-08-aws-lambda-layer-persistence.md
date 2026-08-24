---
title: Detection of Unauthorized AWS Lambda Layer Modifications
slug: 2026-08-aws-lambda-layer-persistence
description: Adversaries with compromised credentials may modify AWS Lambda configurations by injecting unauthorized layers to establish persistence, run arbitrary code, or intercept data.
date: "2026-08-24T09:47:20Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - lambda
  - persistence
  - execution
vendors:
  - Amazon
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1648
    technique_name: Serverless Execution
    evidence: Lambda layers allow shared code, dependencies, or runtime modifications to be injected into a function's execution environment.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578.005
    technique_name: Modify Cloud Compute Configurations
    evidence: Adversaries with the ability to update function configurations may add a malicious layer to establish persistence, run unauthorized code, or intercept data.
    confidence_band: high
references:
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-lambda-persistence/aws-lambda-layers-persistence
  - https://docs.aws.amazon.com/lambda/latest/api/API_PublishLayerVersion.html
  - https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.html
rules:
  - title: Detect Unauthorized AWS Lambda Layer Modifications
    description: Detects when a Lambda layer is added or a function is updated using AWS CloudTrail, excluding activity from known IaC tools like Terraform or Pulumi.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1578.005
      - T1648
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy rule to identify manual Lambda layer changes.
      owner: Detection Engineering
      due: 7d
      evidence: Rule defined in brief.
  hunt_leads:
    - lead: Search CloudTrail logs for all UpdateFunctionConfiguration events over the past 30 days.
      technique_id: T1578.005
      data_needed:
        - CloudTrail logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source provides query parameters to identify Lambda modifications.
---

Adversaries possessing sufficient permissions to interact with the AWS Lambda API can exploit the service's layer architecture to maintain stealthy persistence. By adding a malicious or unauthorized Lambda layer to an existing function, an attacker can inject code into the function's execution environment without modifying the primary source code. This technique allows for the interception of sensitive data, execution of unauthorized backend tasks, or modification of function output.

This activity is often identified via AWS CloudTrail events where `UpdateFunctionConfiguration` or `PublishLayerVersion` actions occur outside of established CI/CD pipelines. Because Lambda layers are designed for legitimate code sharing and dependency management, monitoring requires distinguishing between automated infrastructure-as-code (IaC) deployments and manual or anomalous API requests. Security teams should prioritize visibility into configuration changes originating from non-authorized identities or unexpected source IP addresses.

## Impact

Successful exploitation allows attackers to persist within a serverless environment, potentially leading to long-term data exfiltration or the subversion of internal business logic. The impact is significant for organizations relying heavily on serverless architectures, where such modifications can remain undetected if not monitored at the API level.

## Recommendation

- Deploy the provided detection logic to monitor for AWS Lambda configuration updates that do not originate from known CI/CD or IaC tooling.
- Audit existing Lambda functions to identify currently attached layers that do not map to authorized internal code repositories.
- Implement IAM policies that restrict the ability to modify Lambda configurations and publish new layers to specific, highly-privileged automation service roles.
- Establish a baseline of expected deployment activity to reduce noise from routine CI/CD releases.
