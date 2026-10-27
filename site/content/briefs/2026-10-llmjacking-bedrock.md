---
brief_id: brief-2026-10-27-llmjacking-bedrock
event_id: brief-2026-10-27-llmjacking-bedrock
revision: 1
activity_at: "2026-10-27T23:35:02Z"
title: 'Amazon Bedrock: Unauthorized Model Inference (LLMjacking)'
slug: 2026-10-llmjacking-bedrock
description: LLMjacking operators utilize compromised AWS credentials to perform unauthorized model inference, characterized by a single identity invoking Amazon Bedrock from geographically dispersed source IPs.
date: "2026-10-27T23:35:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Logic validated against provided CloudTrail detection guidance
tags:
  - llmjacking
  - cloud
  - aws
  - credential-access
vendors:
  - Amazon
products:
  - Amazon Bedrock
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: LLMjacking operators often distribute stolen AWS credentials across proxies or resell them to multiple buyers, which produces inference traffic for one identity from many unrelated locations.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: This pattern fits credentials that have been shared, resold, or proxied for LLMjacking.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_bedrock_invocation_high_number_of_countries.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Configure CloudTrail monitoring for Bedrock inference events
      owner: Detection Engineering
      due: 48h
      evidence: Bedrock runtime operations are logged as management events by default.
  hunt_leads:
    - lead: Identify IAM identities showing high geographic entropy in Bedrock invocations
      technique_id: T1528
      data_needed:
        - AWS CloudTrail (Management Events)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: One AWS principal invoked Amazon Bedrock models from at least three countries and three source IPs inside the lookback window.
  mitigation_plan:
    - priority: immediate
      action: Rotate access keys and revoke active sessions for identified compromised principals
      owner: IT Operations
      addresses: Credential theft/LLMjacking
      evidence: If the activity is not explained, deactivate the access key or revoke the role session, rotate credentials, and restrict bedrock:InvokeModel* permissions.
---

LLMjacking involves threat actors gaining unauthorized access to Amazon Bedrock through stolen AWS credentials. These actors often distribute access tokens across proxy networks or resell them, resulting in high-volume inference requests originating from a wide array of global IP addresses. This activity increases operational costs and leverages the compromised identity for unauthorized Generative AI consumption.

## Impact

- Unauthorized financial expenditure due to excessive model inference calls.
- Potential leakage of proprietary information or data sent to models via compromised accounts.
- Risk of further account compromise if the principal has broader IAM permissions beyond Bedrock access.

## Recommendation

- Monitor AWS CloudTrail management events for `InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, and `ConverseStream` actions.
- Implement alerts for IAM principals or roles exhibiting activity from three or more unique countries and source IPs within a 4-hour window.
- Investigate principals flagged for this behavior by checking `aws_cloudtrail.user_identity.access_key_id` consistency across disparate geographic regions.
- Enforce Principle of Least Privilege for Bedrock access, ensuring service-linked roles are scoped to necessary regions and functions.
- Configure AWS Budgets to detect and trigger alerts on abnormal spend associated with Bedrock usage.
