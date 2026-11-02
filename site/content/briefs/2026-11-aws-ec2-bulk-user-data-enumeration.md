---
brief_id: brief-2026-11-02-aws-ec2-bulk-user-data-enumeration
event_id: brief-2026-11-02-aws-ec2-bulk-user-data-enumeration
revision: 1
activity_at: "2026-11-02T21:10:02Z"
title: AWS EC2 Bulk User Data Enumeration
slug: 2026-11-aws-ec2-bulk-user-data-enumeration
description: This detection identifies potential reconnaissance or credential harvesting by principals performing bulk retrieval of EC2 user data from more than 20 instances within a 10-minute window.
date: "2026-11-02T21:10:02Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic provided as ES|QL rule in source; environment validation required.
tags:
  - aws
  - cloud
  - cloud-security
  - discovery
  - credential-access
vendors:
  - Amazon
products:
  - AWS EC2
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
    evidence: Identifies when the same AWS principal, from the same source IP, successfully calls EC2 "DescribeInstanceAttribute" for the "userData" attribute against more than 20 distinct instances within a 10-minute lookback.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.005
    subtechnique_name: Cloud Instance Metadata API
    evidence: Instance user data often contains bootstrap scripts and hardcoded credentials, so retrieving it across many instances in a short window can indicate reconnaissance or credential harvesting.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceAttribute.html
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html
  - https://hackingthe.cloud/aws/exploitation/local_ec2_priv_esc_through_user_data
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_ec2_bulk_user_data_enumeration.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Elastic detection rule for DescribeInstanceAttribute bulk monitoring.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 7f6bc52c-fb52-46b5-8081-b78db15af501
  hunt_leads:
    - lead: Hunt for historical bulk DescribeInstanceAttribute calls in CloudTrail logs.
      technique_id: T1552.005
      data_needed:
        - CloudTrail management events (DescribeInstanceAttribute)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Bulk enumeration of user data across a fleet is a high-risk indicator of unauthorized information gathering.
  mitigation_plan:
    - priority: medium
      action: Rotate credentials found in user data and remove secrets from instance configuration.
      owner: IT Operations
      addresses: T1552.005
      evidence: EC2 userData is frequently used for bootstrap scripts and sometimes contains credentials or tokens.
---

The Elastic detection rule monitors AWS CloudTrail logs for the 'DescribeInstanceAttribute' API action when the 'userData' attribute is requested. Bulk enumeration of this attribute is a high-risk activity, as instance user data often contains sensitive bootstrap scripts, hardcoded credentials, or API tokens. The rule triggers when a single principal, identified by ARN and source IP, accesses this attribute for more than 20 distinct EC2 instances in a 10-minute lookback period.

## Impact
Unauthorized access to EC2 user data can lead to the exposure of plain-text secrets, environment-specific configuration tokens, and infrastructure-level credentials, facilitating further privilege escalation or lateral movement within the cloud environment.

## Recommendation
- Deploy the provided Elastic detection logic to monitor CloudTrail for bulk 'DescribeInstanceAttribute' calls.
- Review alerts triggered by this rule for unauthorized principals, particularly those originating from unexpected ASNs or non-standard user agents.
- Investigate the retrieved 'instanceId' values to determine if sensitive production workloads are targeted.
- Implement a policy of least privilege, restricting 'ec2:DescribeInstanceAttribute' access to only those roles that require it for operational health or inventory management.
- Audit existing instance user data and migrate sensitive secrets to dedicated solutions such as AWS Secrets Manager or Systems Manager Parameter Store.
