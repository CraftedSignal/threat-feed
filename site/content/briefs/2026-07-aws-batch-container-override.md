---
title: Unusual AWS Batch Job Container Command Override Detection
slug: 2026-07-aws-batch-container-override
description: This detection targets the abuse of AWS Batch 'containerOverrides.command' parameters by infrequent users to inject malicious commands or data exfiltration logic into production compute environments.
date: "2026-07-31T09:23:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - batch
  - cloudtrail
  - execution
vendors:
  - Amazon
products:
  - AWS Batch
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This flexibility is commonly abused by adversaries to inject malicious commands or exfiltration logic into otherwise legitimate Batch compute environments.
    confidence_band: high
rules:
  - title: Detect AWS Batch Job Submitted with Container Override
    description: Detects the submission of an AWS Batch job with a container command override, a potential method for injecting malicious commands into compute environments.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - cloud
rules_count: 1
---

Adversaries may abuse the AWS Batch `SubmitJob` API to execute arbitrary commands by utilizing the `containerOverrides.command` parameter. By overriding the default command specified in a pre-approved job definition, an attacker can bypass static configuration reviews and infrastructure-as-code (IaC) drift detection tools. Because the underlying job definition remains unchanged, this technique is highly stealthy and allows for the injection of malicious payloads, shell commands, or exfiltration logic into legitimate Batch compute environments. 

Defenders should monitor AWS CloudTrail logs for `SubmitJob` events where the request includes container overrides. This detection brief focuses on identifying instances where an identity performs this action for the first time in the last 7 days, as this behavior is often indicative of reconnaissance or initial access exploitation rather than standard automated pipeline activity.

## Impact

Successful exploitation allows for arbitrary code execution within the Batch compute environment, potentially leading to unauthorized data access, environment manipulation, or exfiltration. The impact depends on the IAM role associated with the Batch execution, which may have excessive permissions to S3 buckets, databases, or other sensitive cloud services.

## Recommendation

- Deploy detection for `SubmitJob` events involving `containerOverrides.command` for identities that have not previously performed this action.
- Review `aws.cloudtrail.request_parameters` for injected commands, including shell metacharacters, `curl`, `wget`, or encoded payloads.
- Implement restrictive IAM policies for `batch:SubmitJob` that utilize `Condition` keys on `batch:Image` and specific job queue ARNs to prevent arbitrary overrides.
- Validate the behavior of automated ETL pipelines and CI/CD systems to distinguish legitimate parameterization from malicious overrides.
