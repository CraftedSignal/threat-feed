---
brief_id: brief-2026-11-25-new-acl-entries
event_id: brief-2026-11-25-new-acl-entries
revision: 1
activity_at: "2026-11-25T16:17:26Z"
title: 'AWS CloudTrail: Monitoring CreateNetworkAclEntry activity'
slug: 2026-11-new-acl-entries
description: This brief provides a detection rule to monitor the creation of new network ACL entries in AWS, a potential indicator of unauthorized network exposure or configuration changes.
date: "2026-11-25T16:17:26Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Detection logic reflects standard AWS CloudTrail event monitoring.
tags:
  - informational
  - cloud
  - aws
  - defense-impairment
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_new_acl_entries.yml
  - https://web.archive.org/web/20240214032736/https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/
rules:
  - title: Detect AWS CreateNetworkAclEntry
    description: Detects the creation of network ACL entries in an AWS account using CloudTrail data, which may indicate unauthorized network exposure or persistence.
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for CreateNetworkAclEntry events in AWS CloudTrail
      owner: Detection Engineering
      due: 48h
      evidence: Rule defined in SigmaHQ repository
---

## Overview

The creation of network Access Control List (ACL) entries is a significant configuration event in AWS environments. While frequently used for legitimate administrative tasks, the ability to modify network traffic flow and visibility makes the 'CreateNetworkAclEntry' API call a point of interest for monitoring potential unauthorized network access or defense impairment.

## Recommendation

- Deploy the provided Sigma rule to your SIEM to monitor AWS CloudTrail for 'CreateNetworkAclEntry' events.
- Establish a baseline of legitimate ACL modifications to reduce false positives originating from authorized infrastructure-as-code deployments or administrative activity.
