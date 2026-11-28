---
brief_id: brief-2026-11-28-aws-ecr-off-hours
event_id: brief-2026-11-28-aws-ecr-off-hours
revision: 1
activity_at: "2026-11-28T20:47:26Z"
title: 'Amazon ECR: Container image uploads outside business hours'
slug: 2026-11-aws-ecr-off-hours
description: This detection monitors for AWS ECR PutImage events occurring outside of standard business hours, which may indicate unauthorized container deployment or compromised credentials.
date: "2026-11-28T20:47:26Z"
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
  validation_status: Detection logic is grounded in specific AWS CloudTrail event data (PutImage).
tags:
  - cloud
  - aws
  - devsecops
vendors:
  - Amazon
products:
  - Elastic Container Registry
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    subtechnique_id: T1204.003
    subtechnique_name: Malicious Image
    evidence: This analytic detects the upload of a new container image to AWS Elastic Container Registry (ECR) outside of standard business hours.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_ecr_container_upload_outside_business_hours.yml
  - https://attack.mitre.org/techniques/T1204/003/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Implement the Splunk detection search for AWS ECR 'PutImage' events outside standard business hours.
      owner: Detection Engineering
      due: 48h
      evidence: Search logic provided in the source analytic.
  hunt_leads:
    - lead: Investigate AWS CloudTrail 'PutImage' logs for users performing container uploads during non-standard hours (20:00-08:00) or weekends.
      technique_id: T1204.003
      data_needed:
        - AWS CloudTrail (PutImage events)
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Container uploads outside business hours can indicate unauthorized or suspicious activity.
---

## Overview

This analytic identifies potential unauthorized container image uploads to Amazon Elastic Container Registry (ECR) by monitoring AWS CloudTrail 'PutImage' events that occur outside standard business hours (8 PM to 8 AM) or on weekends. This behavior may indicate an insider threat or compromised account being used to deploy malicious container images.

## Impact

If confirmed malicious, unauthorized container uploads can lead to the deployment of malicious workloads, resulting in potential data breaches or service disruptions within the AWS environment.

## Recommendation

- Deploy the monitoring logic for 'PutImage' events in AWS CloudTrail to identify off-hours container management activity.
- Review identified events for legitimacy, particularly in environments with distributed teams spanning multiple time zones, where this detection may generate false positives.
- Investigate the source IP and user context associated with off-hours uploads using the provided drilldown search capability.
