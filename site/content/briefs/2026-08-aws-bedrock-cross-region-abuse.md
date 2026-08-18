---
title: Detection of Potential Cross-Region Inference Abuse in Amazon Bedrock
slug: 2026-08-aws-bedrock-cross-region-abuse
description: Detection of potential cross-region inference abuse in Amazon Bedrock Claude models, which may indicate attempts to bypass regional security controls or perform unauthorized data processing.
date: "2026-08-18T20:47:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - bedrock
  - claude
  - ai-security
vendors:
  - Amazon
products:
  - Amazon Bedrock
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1599
    technique_name: Network Boundary Bridging
    evidence: Cross-region inference abuse may indicate attempts to bypass regional restrictions, exfiltrate data, or perform unauthorized actions across different AWS regions.
    confidence_band: med
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/aws_bedrock_claude_cross_region_possible_inference_abuse.yml
  - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Enable and centralize AWS Bedrock model invocation logging for visibility.
      owner: Cloud Security
      due: 7d
      evidence: https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
  hunt_leads:
    - lead: Identify all requests where origin_region != inference_region and input_tokens > 2000.
      technique_id: T1599
      data_needed:
        - AWS Bedrock model invocation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source detection search logic.
  mitigation_plan:
    - priority: medium_term
      action: Implement Service Control Policies (SCPs) to restrict Bedrock access to authorized regions.
      owner: Cloud Security
      addresses: Cross-region inference
      evidence: General cloud security best practice for region restriction.
---

This detection focuses on identifying suspicious cross-region inference activity within Amazon Bedrock, specifically targeting the Claude model family. Cross-region inference abuse occurs when a user or principal executes inference tasks in an AWS region that differs from the primary region of the request origin. This behavior may be indicative of attempts to bypass regional governance policies, evade localized monitoring, or exfiltrate data by leveraging infrastructure in regions with different compliance or logging postures. Defenders should monitor for large-volume input token requests that exhibit a geographic mismatch between the source and the inference execution region. This activity is relevant for organizations managing multi-region AI infrastructure and ensures that generative AI usage remains within authorized operational boundaries.

## Impact

Successful abuse of this nature could lead to unauthorized use of AI resources, circumvention of organizational data residency requirements, and potential exfiltration of sensitive information processed by large language models. The impact is primarily associated with cloud infrastructure security and compliance violations.

## Recommendation

- Enable Amazon Bedrock model invocation logging to S3 or CloudWatch Logs to capture request and response payloads.
- Ingest AWS Bedrock logs into your SIEM platform using the Splunk Add-on for AWS.
- Review detected cross-region inference events to determine if they are authorized multi-region deployments or anomalous attempts to bypass regional security controls.
- Baseline expected cross-region usage patterns to reduce noise from legitimate development or testing activities.
