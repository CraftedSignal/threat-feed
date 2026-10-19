---
title: Suspicious High-Volume CloudWatch Logs Read Operations
slug: 2026-10-aws-cloudwatch-high-volume-read
description: Detection of anomalous Amazon CloudWatch Logs activity characterized by high-volume API requests, which may indicate automated discovery or exfiltration of sensitive telemetry data.
date: "2026-10-19T02:51:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - data-exfiltration
  - aws
vendors:
  - Amazon
products:
  - CloudWatch Logs
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: It identifies more than 500 DescribeLogGroups, DescribeLogStreams, DownloadLogEvents, FilterLogEvents, GetLogEvents, or GetQueryResults API calls.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1530/
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_repeated_cloudwatch_logs_read_operations.yml
rules:
  - title: Detect High Volume CloudWatch Logs Read Operations
    description: Detects more than 500 CloudWatch Logs read API calls by a single principal within 5 minutes, indicating potential reconnaissance or data collection.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1530
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule for CloudWatch read volume threshold
      owner: Detection Engineering
      due: 72h
      evidence: Source analytic requirement
  hunt_leads:
    - lead: Search for principals with high volume API calls across all AWS regions
      technique_id: T1530
      data_needed:
        - AWS CloudTrail
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source identifies potential discovery behavior
  mitigation_plan:
    - priority: medium
      action: Review IAM permissions for non-essential roles accessing CloudWatch
      owner: IT Operations
      addresses: Excessive logging access
      evidence: Principle of Least Privilege
---

This threat brief focuses on the detection of potential reconnaissance or data exfiltration activities targeting Amazon CloudWatch Logs. Adversaries often target these logs to gain visibility into infrastructure, application logic, and security telemetry. The identified behavior involves an AWS principal or role initiating an excessive number of read operations (more than 500 events) within a five-minute window. Observed API calls include DescribeLogGroups, DescribeLogStreams, DownloadLogEvents, FilterLogEvents, GetLogEvents, and GetQueryResults. While legitimate administrative or automated tasks (such as SIEM pipelines or backup tools) may generate similar traffic, unauthorized spikes warrant investigation to rule out adversary-led discovery or collection of sensitive operational data.

## Impact

Successful exploitation allows unauthorized entities to gain deep insights into an organization's cloud environment, potentially exposing credentials, secrets, or internal system architecture stored within log files. This can facilitate further lateral movement or data exfiltration efforts.

## Recommendation

Detection engineering teams should implement monitoring for high-frequency CloudWatch API usage to identify potential data discovery.

* Deploy the provided detection logic to AWS CloudTrail telemetry to identify principals performing >500 read operations in 5 minutes.
* Establish an allowlist for known-good automation service roles, incident response tooling, and SIEM ingestion service accounts to reduce false positives.
* Audit principals identified by the detection to confirm they are associated with authorized infrastructure tasks rather than anomalous or malicious origins.
