---
brief_id: brief-2026-11-28-aws-iam-delete-policy
event_id: brief-2026-11-28-aws-iam-delete-policy
revision: 1
activity_at: "2026-11-28T20:47:45Z"
title: AWS IAM Delete Policy Monitoring
slug: 2026-11-aws-iam-delete-policy
description: This analytic detects the deletion of an IAM policy in AWS using CloudTrail logs.
date: "2026-11-28T20:47:45Z"
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
tags:
  - cloud
  - aws
  - iam
vendors:
  - Amazon
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: If confirmed malicious, an attacker could remove critical security policies, potentially leading to privilege escalation.
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_iam_delete_policy.yml
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeletePolicy.html
  - https://docs.aws.amazon.com/cli/latest/reference/iam/delete-policy.html
action_plan:
  hunt_leads:
    - lead: Identify instances of IAM policy deletion where the user agent is not associated with AWS internal services to isolate potentially unauthorized configuration changes.
      technique_id: T1098
      data_needed:
        - AWS CloudTrail DeletePolicy events
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Unauthorized policy deletions can disrupt access controls and weaken security postures. If confirmed malicious, an attacker could remove critical security policies, potentially leading to privilege escalation.
---

## Overview

The following analytic detects the deletion of an IAM policy in AWS by leveraging AWS CloudTrail logs to identify 'DeletePolicy' events, excluding those from AWS internal services. Monitoring this behavior ensures that only authorized changes are made to IAM policies.

## Attack Chain

Unauthorized policy deletions can disrupt access controls and weaken security postures. If confirmed malicious, an attacker could remove critical security policies, potentially leading to privilege escalation, unauthorized access, or data exfiltration.

## Impact

Unauthorized policy deletion can lead to the removal of critical security policies, privilege escalation, unauthorized access, or data exfiltration.

## Recommendation

This detection requires tuning to provide high fidelity. It should be tuned based on source addresses (corporate offices, VPN terminations) or by groups of users, as not every user with AWS access should have permission to delete policies. Implementation requires the Splunk AWS Add-on and Splunk App for AWS to process AWS CloudTrail logs.
