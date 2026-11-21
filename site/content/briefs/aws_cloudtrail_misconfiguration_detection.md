---
brief_id: brief-2026-07-aws-cloudtrail-misconfiguration-detection
event_id: brief-2026-07-aws-cloudtrail-misconfiguration-detection
revision: 1
activity_at: "2026-07-14T20:24:11Z"
title: AWS CloudTrail Logging Configuration Changes
slug: aws_cloudtrail_misconfiguration_detection
description: Monitor CloudTrail control-plane events that stop logging, delete a trail, or change its configuration. Investigate unexpected principals and deviations from approved trail settings.
date: "2026-07-14T20:24:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploited: false
exploitation_evidence:
  status: unknown
tags:
  - aws
  - cloudtrail
  - defense-evasion
  - attack.t1562.001
vendors:
  - Amazon
products:
  - AWS CloudTrail
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DeleteTrail.html
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-turning-off-logging.html
rules_count: 0
---

CloudTrail configuration changes can create gaps in audit visibility. Monitor CloudTrail management events for `StopLogging`, `DeleteTrail`, and `UpdateTrail` calls. AWS documents `StopLogging` as suspending event recording and log-file delivery. `DeleteTrail` removes the trail configuration; it does not delete log files already delivered to Amazon S3. `UpdateTrail` changes trail settings and does not require logging to be stopped first.

## Investigation

For each event, review the caller identity, source IP, user agent, event time, AWS Region, and request parameters. For `UpdateTrail`, compare destination and coverage settings—including the S3 bucket, CloudWatch Logs group, KMS key, multi-Region setting, global service events, and log-file validation—with the approved baseline. Confirm that the caller and change match an authorized change record. Treat routine maintenance as expected only after verifying its scope and approval.

A `StopLogging` event is a high-priority signal because recording and delivery are suspended for that trail. A `DeleteTrail` event has a different effect: existing delivered files remain, but a multi-Region trail stops logging across enabled Regions. Delayed events may still arrive after logging is stopped, so their arrival alone does not prove that recording continued.

## Response

* Alert on `StopLogging` and `DeleteTrail` events, and investigate any call from an unexpected principal or source address.
* Alert on `UpdateTrail` changes that move log destinations, reduce Region or event coverage, or disable log-file validation. Tune these checks against a known-good trail configuration to reduce noise from authorized maintenance.
* Verify logging status and trail configuration after the change. Restore the approved settings, preserve available CloudTrail records, and investigate related IAM and CloudTrail control-plane activity.
* Restrict `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, and `cloudtrail:UpdateTrail` permissions to approved administrative roles and protect changes with an auditable approval process.
