---
title: ""
slug: aws_cloudtrail_misconfiguration_detection
description: This rule detects changes to AWS CloudTrail configurations that could indicate a security risk, specifically disabling or altering trails, or failing a security configuration check. Such actions can significantly reduce visibility into AWS activity.
date: "2026-07-14T20:24:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.impact
  - attack.defense_evasion
  - attack.t1562.001
  - attack.t1562.006
vendors:
  - Amazon
products:
  - AWS CloudTrail
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail.html
  - https://aws.amazon.com/cloudtrail/
rules:
  - title: AWS CloudTrail StopLogging or DeleteTrail Event
    description: Detects attempts to stop or delete an AWS CloudTrail, which can lead to a loss of audit visibility.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - aws
      - cloudtrail
  - title: AWS CloudTrail UpdateTrail with Logging Disabled
    description: Detects when an existing AWS CloudTrail's logging is disabled or reconfigured to not log, potentially indicating defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - aws
      - cloudtrail
  - title: AWS CloudTrail UpdateTrail to Exclude Global Service Events
    description: Detects when an AWS CloudTrail is updated to no longer include global service events, potentially hiding activity in services like IAM.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - aws
      - cloudtrail
rules_count: 3
---
