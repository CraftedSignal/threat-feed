---
brief_id: brief-2026-11-28-aws-lambda-update-code
event_id: brief-2026-11-28-aws-lambda-update-code
revision: 1
activity_at: "2026-11-28T20:48:18Z"
title: 'AWS Lambda: UpdateFunctionCode activity monitoring'
slug: 2026-11-aws-lambda-update-code
description: This analytic identifies IAM user attempts to modify AWS Lambda code, a technique potentially used by adversaries to gain persistence or deploy backdoors.
date: "2026-11-28T20:48:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Detection logic relies on AWS CloudTrail logs; requires Splunk AWS Add-on.
tags:
  - cloud
  - aws
  - lambda
  - persistence
vendors:
  - Amazon
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: If confirmed malicious, an attacker could upload and execute malicious code automatically when the Lambda function is triggered.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1204
    technique_name: User Execution
    evidence: This activity is significant as it may indicate an attempt to gain persistence, further access, or plant backdoors within your AWS environment.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_lambda_updatefunctioncode.yml
  - http://detectioninthe.cloud/execution/modify_lambda_function_code/
  - https://sysdig.com/blog/exploit-mitigate-aws-lambdas-mitre/
action_plan:
  priority: enrich_before_decision
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Hunt for IAM users invoking the UpdateFunctionCode API outside of established CI/CD service accounts or known deployment windows.
      technique_id: T1204
      data_needed:
        - AWS CloudTrail (eventName, user_type, user_name, source_ip)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: This activity is significant as it may indicate an attempt to gain persistence, further access, or plant backdoors within your AWS environment.
---

## Overview

The `UpdateFunctionCode` API call in AWS Lambda allows for the modification of function code. This analytic monitors CloudTrail logs for successful `UpdateFunctionCode` events initiated by IAM users. While this action is necessary for legitimate development and administration, unauthorized or unexpected updates may indicate an attempt to gain persistence or plant backdoors within a serverless environment.

## Impact

If the activity is confirmed malicious, an attacker could upload and execute arbitrary code that triggers automatically whenever the Lambda function is invoked, leading to potential compromise of the integrity and security of the AWS infrastructure.

## Recommendation

Detection teams should monitor CloudTrail logs for `UpdateFunctionCode` events. Legitimate administrative activity should be baselined to reduce false positives. Install the Splunk AWS Add-on to ingest required CloudTrail telemetry. Review successful code updates against expected CI/CD deployment windows and authorized IAM user roles.
