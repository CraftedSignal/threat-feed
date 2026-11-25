---
brief_id: brief-2026-11-25-rds-sg-modification
event_id: brief-2026-11-25-rds-sg-modification
revision: 1
activity_at: "2026-11-25T16:18:01Z"
title: AWS RDS Security Group Configuration Changes
slug: 2026-11-rds-sg-modification
description: Administrative modifications to RDS security groups via CloudTrail API calls can lead to unauthorized public exposure or denial of service to database instances.
date: "2026-11-25T16:18:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_security_group_change_rds.yml
rules:
  - title: RDS Database Security Group Modification
    description: Detects changes to the security group entries for RDS databases. This can indicate that a misconfiguration has occurred which potentially exposes the database to the public internet, a wider audience within the VPC or that removal of valid rules has occurred which could impact the availability of the database to legitimate services and users.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1190
    data_sources:
      - aws
      - cloudtrail
rules_count: 1
---

## Overview

AWS CloudTrail logs record administrative modifications to RDS Database Security Groups. These events include the creation and deletion of security groups, as well as the authorization or revocation of ingress rules.

## Attack Chain

Unauthorized or accidental modifications to RDS Security Group rules may result in the exposure of databases to the public internet or broader network segments, or the disruption of service availability due to rule removal.

## Impact

Changes to security group configurations can facilitate unauthorized network access to database instances or deny legitimate services and users access to the database.

## Recommendation

Monitor CloudTrail logs for events indicative of RDS security group modifications to ensure changes align with authorized operational procedures.
