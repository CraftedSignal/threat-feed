---
brief_id: brief-2026-11-25-lb-sg-mod
event_id: brief-2026-11-25-lb-sg-mod
revision: 1
activity_at: "2026-11-25T16:17:53Z"
title: AWS Load Balancer Security Group Modification Monitoring
slug: 2026-11-lb-sg-mod
description: Cloud infrastructure modifications affecting Elastic Load Balancer security groups can signal potential misconfigurations or unauthorized attempts to expose VPC subnets to broader network traffic.
date: "2026-11-25T16:17:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Detection logic reflects documented AWS CloudTrail patterns.
vendors:
  - Amazon
products:
  - AWS Elastic Load Balancing
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This can indicate that a misconfiguration allowing more traffic into the system than required, or could indicate that an attacker is attempting to enable new connections into a VPC or subnet controlled by the account.
    confidence_band: med
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_security_group_change_loadbalancer.yml
rules:
  - title: Detect Load Balancer Security Group Modifications
    description: Detects changes to the security groups associated with an Elastic Load Balancer (ELB) or Application Load Balancer (ALB) in AWS CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Deploy the Sigma rule to the SIEM and enable alerting for high-risk accounts.
      owner: Detection Engineering
  hunt_leads:
    - lead: Identify irregular or off-hours modifications to ELB security groups, specifically those not associated with known infrastructure-as-code deployment pipelines.
      technique_id: T1190
      data_needed:
        - CloudTrail event source, event name, user identity, and source IP address
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Changes to security groups to allow for new services to be deployed can be monitored via CloudTrail events.
---

## Overview

Unauthorized or unexpected modifications to security groups associated with AWS Elastic Load Balancer (ELB) and Application Load Balancer (ALB) infrastructure may indicate an attempt to expand network ingress points. These modifications, specifically targeting 'ApplySecurityGroupsToLoadBalancer' and 'SetSecurityGroups' API calls, can be used by an attacker to bypass existing network segmentation or establish access to previously unreachable VPC resources. Monitoring these specific CloudTrail events is essential for detecting configuration drift or potential reconnaissance and access escalation activities.
